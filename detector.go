package lagguard

import (
	"fmt"
	"time"
)

const stampSlotCount = 512

type stampSlot struct {
	seq   uint64
	stamp time.Duration
	ok    bool
}

type burstState struct {
	active bool
	opened bool
	id     string

	triggerGap  time.Duration
	seqBefore   uint64
	firstSeq    uint64
	companion   int
	probesSent  int
	probesReply int

	start time.Time
	last  time.Time

	firstStamp time.Duration
	lastStamp  time.Duration

	count int

	samples int
	changes int
	actions int
	retrans int
	fec     int

	opponentFrameGap time.Duration
	serverTickGap    time.Duration
	rollbackEvents   int

	minSeq         uint64
	maxSeq         uint64
	lastArrivalSeq uint64
	outOfOrder     bool
	haveMinMax     bool

	seen        map[uint64]struct{}
	stampDeltas []time.Duration
	signals     []Signal
}

// Detector is a fixed-memory, allocation-light per-stream detector. It is not
// safe for concurrent use; the gateway's per-stream goroutine should own it.
type Detector struct {
	cfg       Config
	sessionID string

	packets uint64

	lastObservedAt time.Time
	haveArrival    bool
	haveSeq        bool
	lastRecv       time.Time
	lastSeq        uint64

	arrivalIntervals *floatRing
	stampIntervals   *floatRing
	rttSamples       *floatRing
	stampSlots       [stampSlotCount]stampSlot

	baselineRTT   time.Duration
	baselinePPS   float64
	baselineStamp time.Duration
	lossRate      float64
	access        AccessNetwork
	lastReportAt  time.Time
	networkReport NetworkReport
	haveReport    bool

	burst burstState

	incidentSeq   uint64
	incidentTimes []time.Time
}

// NewDetector creates a detector for one session/stream.
func NewDetector(sessionID string, cfg Config) *Detector {
	cfg = normalizeConfig(cfg)
	return &Detector{
		cfg:              cfg,
		sessionID:        sessionID,
		arrivalIntervals: newFloatRing(128),
		stampIntervals:   newFloatRing(128),
		rttSamples:       newFloatRing(64),
		access:           AccessUnknown,
	}
}

func normalizeConfig(cfg Config) Config {
	def := DefaultConfig()
	if cfg.GapThreshold <= 0 {
		cfg.GapThreshold = def.GapThreshold
	}
	if cfg.BurstInterPacketGap <= 0 {
		cfg.BurstInterPacketGap = def.BurstInterPacketGap
	}
	if cfg.BurstInterPacketGap >= cfg.GapThreshold {
		cfg.BurstInterPacketGap = cfg.GapThreshold / 4
	}
	if cfg.BurstWindow <= 0 {
		cfg.BurstWindow = def.BurstWindow
	}
	if cfg.MinBurstPackets <= 0 {
		cfg.MinBurstPackets = def.MinBurstPackets
	}
	if cfg.MinBurstPPSFactor <= 0 {
		cfg.MinBurstPPSFactor = def.MinBurstPPSFactor
	}
	if cfg.MinSpanRatio <= 0 {
		cfg.MinSpanRatio = def.MinSpanRatio
	}
	if cfg.MinAccumulatedSpan <= 0 {
		cfg.MinAccumulatedSpan = def.MinAccumulatedSpan
	}
	if cfg.StampTolerance <= 0 {
		cfg.StampTolerance = def.StampTolerance
	}
	if cfg.StateChangesPerPacket <= 0 {
		cfg.StateChangesPerPacket = def.StateChangesPerPacket
	}
	if cfg.RepeatWindow <= 0 {
		cfg.RepeatWindow = def.RepeatWindow
	}
	if cfg.ObserveScore <= 0 {
		cfg.ObserveScore = def.ObserveScore
	}
	if cfg.ReviewScore <= 0 {
		cfg.ReviewScore = def.ReviewScore
	}
	if cfg.HoldScore <= 0 {
		cfg.HoldScore = def.HoldScore
	}
	if cfg.KickScore <= 0 {
		cfg.KickScore = def.KickScore
	}
	return cfg
}

// ObserveNetwork supplies periodic network/transport telemetry.
func (d *Detector) ObserveNetwork(r NetworkReport) {
	if r.At.IsZero() {
		r.At = time.Now()
	}
	d.networkReport = r
	d.haveReport = true
	d.lastReportAt = r.At
	if r.Access != "" {
		d.access = r.Access
	}
	d.lossRate = clamp01(r.LossRate)
	if r.RTT > 0 {
		d.rttSamples.add(r.RTT.Seconds())
		if med, ok := d.rttSamples.median(); ok {
			d.baselineRTT = time.Duration(med * float64(time.Second))
		}
	}
}

// Observe processes one input packet metadata record. It never performs IO.
func (d *Detector) Observe(p Packet) Result {
	d.packets++
	if p.RecvAt.IsZero() {
		p.RecvAt = time.Now()
	}
	d.lastObservedAt = p.RecvAt

	tsSignals, stampDelta := d.checkTimestamps(p)
	var incidents []*Incident

	arrivalDelta := time.Duration(0)
	if d.haveArrival {
		arrivalDelta = p.RecvAt.Sub(d.lastRecv)
	}
	isGap := d.haveArrival && arrivalDelta >= d.cfg.GapThreshold

	// Close an earlier burst before classifying the new arrival.
	if d.burst.active && (isGap || d.shouldCloseForArrival(p.RecvAt)) {
		if inc := d.completeBurst(); inc != nil {
			incidents = append(incidents, inc)
		}
		d.resetBurst()
	}

	var opened *Incident
	switch {
	case isGap:
		d.startBurst(p, arrivalDelta, d.lastSeq, tsSignals, stampDelta)

	case d.burst.active:
		d.addBurst(p, stampDelta, tsSignals)

	default:
		if d.haveArrival && arrivalDelta > 0 && arrivalDelta < d.cfg.GapThreshold {
			d.arrivalIntervals.add(arrivalDelta.Seconds())
		}
		if stampDelta > 0 && stampDelta < d.cfg.GapThreshold {
			d.stampIntervals.add(stampDelta.Seconds())
		}
		if len(tsSignals) > 0 {
			opened = d.newIntegrityIncident(p, tsSignals)
			incidents = append(incidents, opened)
		}
	}

	// Open a burst incident as soon as the minimum evidence is present so an
	// inline normalizer can react before the entire flood has been forwarded.
	if d.burst.active && !d.burst.opened && d.burst.count >= d.cfg.MinBurstPackets {
		candidate := d.buildBurstIncident(false)
		// Open on the un-exonerated shape score so reviewers can also inspect
		// episodes that network evidence subsequently classifies as benign.
		if candidate.Decision.Score >= d.cfg.ObserveScore || hasHardSignal(candidate.Signals) {
			d.burst.opened = true
			d.burst.id = candidate.ID
			d.noteIncidentTime(candidate.StartedAt)
			opened = candidate
			incidents = append(incidents, candidate)
		}
	}

	// An already-open burst can gain a hard timestamp signal after opening.
	// If this call itself opened the incident, that candidate already contains
	// the signal and must not be recorded twice.
	if opened == nil && d.burst.active && d.burst.opened && hasHardSignal(tsSignals) {
		updated := d.buildBurstIncident(false)
		opened = updated
		incidents = append(incidents, updated)
	}

	d.haveArrival = true
	d.lastRecv = p.RecvAt
	d.haveSeq = true
	d.lastSeq = p.Seq
	if d.packets%64 == 0 {
		d.refreshBaselines()
	}

	primary := pickPrimary(incidents, opened)
	decision := Decision{Primary: ActionPass, Actions: []Action{ActionPass}, Confidence: 1}
	if primary != nil {
		decision = primary.Decision
	}
	if len(incidents) == 0 {
		incidents = nil
	}
	return Result{
		Incident:  primary,
		Incidents: incidents,
		Decision:  decision,
		Metrics:   d.Metrics(),
	}
}

// Flush closes and returns the active burst, if one had become an incident.
// Gateways should call this on stream shutdown or on a periodic timer.
func (d *Detector) Flush() *Incident {
	if !d.burst.active {
		return nil
	}
	inc := d.completeBurst()
	d.resetBurst()
	return inc
}

// Metrics returns current operational metrics. It is allocation-free on the
// packet fast path; robust medians are refreshed periodically and while scoring
// an incident, not for every packet.
func (d *Detector) Metrics() Metrics {
	return Metrics{
		PacketsObserved:  d.packets,
		Incidents:        len(d.incidentTimes),
		BaselineInterval: d.baselineStampInterval(),
		BaselinePPS:      d.baselinePPS,
		BaselineRTT:      d.baselineRTT,
		RecentLossRate:   d.lossRate,
		Access:           d.access,
	}
}

func (d *Detector) refreshBaselines() {
	if d.cfg.ExpectedStampInterval > 0 {
		d.baselineStamp = d.cfg.ExpectedStampInterval
	} else if med, ok := d.stampIntervals.median(); ok && med > 0 {
		d.baselineStamp = time.Duration(med * float64(time.Second))
	}

	if med, ok := d.arrivalIntervals.median(); ok && med > 0 {
		d.baselinePPS = 1 / med
	} else if d.baselineStamp > 0 {
		d.baselinePPS = float64(time.Second) / float64(d.baselineStamp)
	}
}

func (d *Detector) checkTimestamps(p Packet) ([]Signal, time.Duration) {
	var signals []Signal
	idx := p.Seq & (stampSlotCount - 1)
	old := d.stampSlots[idx]
	if old.ok && old.seq == p.Seq {
		if old.stamp != p.ClientStamp {
			signals = append(signals, Signal{
				Code:   "TIMESTAMP_MUTATED_ON_DUPLICATE",
				Title:  "同一序列号的时间戳被改写",
				Detail: "重传/重复数据包的客户端时间戳与首次观测不一致；真实重传必须保持原时间戳。",
				Points: 52,
				Hard:   true,
				Data: map[string]float64{
					"original_stamp_ms": float64(old.stamp.Milliseconds()),
					"observed_stamp_ms": float64(p.ClientStamp.Milliseconds()),
				},
				Seqs: []uint64{p.Seq},
			})
		}
		// Do not overwrite the first observation.
		return signals, 0
	}
	d.stampSlots[idx] = stampSlot{seq: p.Seq, stamp: p.ClientStamp, ok: true}

	prevIdx := (p.Seq - 1) & (stampSlotCount - 1)
	prev := d.stampSlots[prevIdx]
	if !prev.ok || prev.seq != p.Seq-1 {
		return signals, 0
	}
	delta := p.ClientStamp - prev.stamp
	if delta < -d.cfg.StampTolerance {
		signals = append(signals, Signal{
			Code:   "TIMESTAMP_NON_MONOTONIC_BY_SEQ",
			Title:  "时间戳与序列号顺序矛盾",
			Detail: "按序列号相邻的输入包出现显著回退；普通乱序不会改变相邻序列号的单调生成时间。",
			Points: 38,
			Hard:   true,
			Data: map[string]float64{
				"delta_ms":     float64(delta.Milliseconds()),
				"tolerance_ms": float64(d.cfg.StampTolerance.Milliseconds()),
			},
			Seqs: []uint64{prev.seq, p.Seq},
		})
	} else if delta == 0 && d.cfg.ExpectedStampInterval > 0 {
		signals = append(signals, Signal{
			Code:   "TIMESTAMP_DUPLICATED_FOR_DISTINCT_SEQ",
			Title:  "不同序列号使用相同时间戳",
			Detail: "两个连续序列号具有完全相同的时间戳；可能是合并采样，也可能是伪造抖动。",
			Points: 8,
			Data:   map[string]float64{"seq": float64(p.Seq)},
			Seqs:   []uint64{prev.seq, p.Seq},
		})
	}
	return signals, delta
}

func (d *Detector) shouldCloseForArrival(now time.Time) bool {
	b := &d.burst
	if b.count == 0 {
		return false
	}
	if now.Sub(b.last) > d.cfg.BurstInterPacketGap {
		return true
	}
	return now.Sub(b.start) > d.cfg.BurstWindow
}

func (d *Detector) startBurst(p Packet, gap time.Duration, seqBefore uint64, ts []Signal, stampDelta time.Duration) {
	seen := make(map[uint64]struct{}, d.cfg.MinBurstPackets*2)
	seen[p.Seq] = struct{}{}
	d.burst = burstState{
		active:           true,
		triggerGap:       gap,
		seqBefore:        seqBefore,
		firstSeq:         p.Seq,
		companion:        p.CompanionPacketsInGap,
		probesSent:       p.ProbesSentInGap,
		probesReply:      p.ProbeResponsesInGap,
		start:            p.RecvAt,
		last:             p.RecvAt,
		firstStamp:       p.ClientStamp,
		lastStamp:        p.ClientStamp,
		count:            1,
		samples:          maxInt(1, p.Samples),
		changes:          p.StateChanges,
		actions:          p.ActionEvents,
		retrans:          boolToInt(p.IsRetransmission),
		fec:              boolToInt(p.FECRecovered),
		opponentFrameGap: p.OpponentFrameGap,
		serverTickGap:    p.ServerTickGap,
		rollbackEvents:   p.RollbackEvents,
		minSeq:           p.Seq,
		maxSeq:           p.Seq,
		lastArrivalSeq:   p.Seq,
		haveMinMax:       true,
		seen:             seen,
		signals:          append([]Signal(nil), ts...),
	}
	if stampDelta != 0 {
		d.burst.stampDeltas = append(d.burst.stampDeltas, stampDelta)
	}
}

func (d *Detector) addBurst(p Packet, stampDelta time.Duration, ts []Signal) {
	b := &d.burst
	b.last = p.RecvAt
	b.lastStamp = p.ClientStamp
	b.count++
	b.samples += maxInt(1, p.Samples)
	b.changes += p.StateChanges
	b.actions += p.ActionEvents
	if p.IsRetransmission {
		b.retrans++
	}
	if p.FECRecovered {
		b.fec++
	}
	if p.OpponentFrameGap > b.opponentFrameGap {
		b.opponentFrameGap = p.OpponentFrameGap
	}
	if p.ServerTickGap > b.serverTickGap {
		b.serverTickGap = p.ServerTickGap
	}
	if p.RollbackEvents > b.rollbackEvents {
		b.rollbackEvents = p.RollbackEvents
	}
	if !b.haveMinMax {
		b.minSeq, b.maxSeq = p.Seq, p.Seq
		b.haveMinMax = true
	} else {
		if p.Seq < b.minSeq {
			b.minSeq = p.Seq
		}
		if p.Seq > b.maxSeq {
			b.maxSeq = p.Seq
		}
		if p.Seq < b.lastArrivalSeq {
			b.outOfOrder = true
		}
	}
	b.lastArrivalSeq = p.Seq
	if _, exists := b.seen[p.Seq]; !exists {
		b.seen[p.Seq] = struct{}{}
	}
	if stampDelta != 0 && len(b.stampDeltas) < 64 {
		b.stampDeltas = append(b.stampDeltas, stampDelta)
	}
	b.signals = append(b.signals, ts...)
}

func (d *Detector) resetBurst() {
	d.burst = burstState{}
}

func (d *Detector) completeBurst() *Incident {
	if !d.burst.active {
		return nil
	}
	if !d.burst.opened && d.burst.count >= d.cfg.MinBurstPackets {
		candidate := d.buildBurstIncident(true)
		if candidate.Decision.Score >= d.cfg.ObserveScore || hasHardSignal(candidate.Signals) {
			d.burst.opened = true
			d.burst.id = candidate.ID
			d.noteIncidentTime(candidate.StartedAt)
		}
	}
	if !d.burst.opened {
		return nil
	}
	inc := d.buildBurstIncident(true)
	inc.ID = d.burst.id
	inc.Complete = true
	inc.Decision = d.decide(inc)
	return inc
}

func (d *Detector) newIntegrityIncident(p Packet, signals []Signal) *Incident {
	d.incidentSeq++
	id := fmt.Sprintf("%s-ts-%d-%d", d.sessionID, d.incidentSeq, p.Seq)
	now := p.RecvAt
	inc := &Incident{
		ID:          id,
		SessionID:   d.sessionID,
		StartedAt:   now,
		EndedAt:     now,
		Complete:    true,
		FirstSeq:    p.Seq,
		LastSeq:     p.Seq,
		MinSeq:      p.Seq,
		MaxSeq:      p.Seq,
		PacketCount: 1,
		Signals:     append([]Signal(nil), signals...),
	}
	inc.RepeatedCount = d.noteIncidentTime(now)
	d.addNetworkExonerators(inc)
	inc.Decision = d.decide(inc)
	return inc
}

func (d *Detector) noteIncidentTime(t time.Time) int {
	d.incidentTimes = append(d.incidentTimes, t)
	cutoff := t.Add(-d.cfg.RepeatWindow)
	kept := d.incidentTimes[:0]
	for _, old := range d.incidentTimes {
		if !old.Before(cutoff) {
			kept = append(kept, old)
		}
	}
	d.incidentTimes = kept
	return len(d.incidentTimes)
}

func (d *Detector) recentIncidentCount(t time.Time) int {
	cutoff := t.Add(-d.cfg.RepeatWindow)
	count := 0
	for _, old := range d.incidentTimes {
		if !old.Before(cutoff) {
			count++
		}
	}
	return count
}

func (d *Detector) baselineStampInterval() time.Duration {
	if d.cfg.ExpectedStampInterval > 0 {
		return d.cfg.ExpectedStampInterval
	}
	return d.baselineStamp
}

func pickPrimary(list []*Incident, opened *Incident) *Incident {
	if opened != nil {
		return opened
	}
	if len(list) > 0 {
		// The completed incident is usually the only element. If several
		// exist, return the one with the highest adjusted score.
		best := list[0]
		for _, inc := range list[1:] {
			if inc.Decision.AdjustedScore > best.Decision.AdjustedScore {
				best = inc
			}
		}
		return best
	}
	return nil
}

func hasHardSignal(signals []Signal) bool {
	for _, s := range signals {
		if s.Hard {
			return true
		}
	}
	return false
}

func boolToInt(v bool) int {
	if v {
		return 1
	}
	return 0
}

func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func seqRange(lo, hi uint64, limit int) []uint64 {
	if hi < lo || limit <= 0 {
		return nil
	}
	span := hi - lo + 1
	if span <= uint64(limit) {
		out := make([]uint64, 0, span)
		for seq := lo; seq <= hi; seq++ {
			out = append(out, seq)
			if seq == hi {
				break
			}
		}
		return out
	}
	out := make([]uint64, 0, limit)
	step := span / uint64(limit)
	if step == 0 {
		step = 1
	}
	for i := 0; i < limit; i++ {
		out = append(out, lo+uint64(i)*step)
	}
	out[len(out)-1] = hi
	return out
}
