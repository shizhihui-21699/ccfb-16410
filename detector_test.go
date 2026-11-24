package lagguard

import (
	"testing"
	"time"
)

func feedBaseline(t *testing.T, d *Detector, n int, interval time.Duration, base time.Time) {
	t.Helper()
	for seq := uint64(1); seq <= uint64(n); seq++ {
		d.Observe(Packet{
			Seq:         seq,
			RecvAt:      base.Add(time.Duration(seq) * interval),
			ClientStamp: time.Duration(seq) * interval,
		})
	}
}

func findSignal(inc *Incident, code string) *Signal {
	if inc == nil {
		return nil
	}
	for i := range inc.Signals {
		if inc.Signals[i].Code == code {
			return &inc.Signals[i]
		}
	}
	return nil
}

func TestHoldThenBurstIsFlaggedForReview(t *testing.T) {
	cfg := DefaultConfig().WithInputRate(60)
	d := NewDetector("match-1-player-a", cfg)
	base := time.Unix(1700000000, 0).UTC()
	interval := 16 * time.Millisecond
	feedBaseline(t, d, 24, interval, base)

	gapStart := base.Add(24 * interval).Add(450 * time.Millisecond)
	var opened *Incident
	for i := 0; i < 16; i++ {
		seq := uint64(25 + i)
		res := d.Observe(Packet{
			Seq:          seq,
			RecvAt:       gapStart.Add(time.Duration(i) * 2 * time.Millisecond),
			ClientStamp:  time.Duration(seq) * interval,
			ActionEvents: 0,
		})
		if res.Incident != nil && opened == nil {
			opened = res.Incident
		}
	}
	final := d.Flush()
	if opened == nil {
		t.Fatal("expected burst incident to open before flood ended")
	}
	if findSignal(opened, "ARRIVAL_GAP_THEN_PACKET_BURST") == nil {
		t.Fatalf("missing arrival burst signal: %+v", opened.Signals)
	}
	if findSignal(opened, "TIME_COMPRESSION_BURST") == nil {
		t.Fatalf("missing time compression signal: %+v", opened.Signals)
	}
	if opened.Decision.Primary != ActionFlagReview && opened.Decision.Primary != ActionHoldForReview {
		t.Fatalf("expected review/hold, got %s score=%d", opened.Decision.Primary, opened.Decision.AdjustedScore)
	}
	if !opened.Decision.ReviewRequired {
		t.Fatal("expected review to be required")
	}
	if final == nil || !final.Complete {
		t.Fatalf("expected completed flush incident, got %+v", final)
	}
}

func TestRealLossAndHandoverIsExonerated(t *testing.T) {
	cfg := DefaultConfig().WithInputRate(60)
	d := NewDetector("match-2-player-b", cfg)
	base := time.Unix(1700000100, 0).UTC()
	interval := 16 * time.Millisecond
	feedBaseline(t, d, 24, interval, base)

	for i := 0; i < 5; i++ {
		d.ObserveNetwork(NetworkReport{
			At:     base.Add(time.Duration(i) * time.Second),
			RTT:    30 * time.Millisecond,
			Access: AccessWiFi,
		})
	}
	d.ObserveNetwork(NetworkReport{
		At:       base.Add(6 * time.Second),
		RTT:      110 * time.Millisecond,
		LossRate: 0.18,
		Access:   AccessWiFi,
	})

	// Nine sequence numbers are lost: 25..34 do not arrive.
	first := uint64(35)
	gapStart := base.Add(24 * interval).Add(450 * time.Millisecond)
	var inc *Incident
	for i := 0; i < 10; i++ {
		res := d.Observe(Packet{
			Seq:         first + uint64(i),
			RecvAt:      gapStart.Add(time.Duration(i) * 2 * time.Millisecond),
			ClientStamp: time.Duration(first+uint64(i)) * interval,
		})
		if res.Incident != nil {
			inc = res.Incident
		}
	}
	if inc == nil {
		inc = d.Flush()
	}
	if inc == nil {
		t.Fatal("expected incident for visible burst shape")
	}
	if findSignal(inc, "REAL_NETWORK_SEQUENCE_LOSS") == nil {
		t.Fatalf("expected sequence-loss exonerator, signals=%+v", inc.Signals)
	}
	if inc.Decision.NetworkEvidenceLevel != EvidenceStrong {
		t.Fatalf("expected strong network evidence, got %q", inc.Decision.NetworkEvidenceLevel)
	}
	if inc.Decision.Primary == ActionKick || inc.Decision.Primary == ActionHoldForReview || inc.Decision.Primary == ActionFlagReview {
		t.Fatalf("weak-network player must not be sanctioned, got %s score=%d", inc.Decision.Primary, inc.Decision.AdjustedScore)
	}
	if inc.Decision.ReviewRequired {
		t.Fatal("strong real-network evidence should not enter punitive review")
	}
}

func TestForgedStampsMatchingBurstArrivalCadence(t *testing.T) {
	cfg := DefaultConfig().WithInputRate(60)
	d := NewDetector("match-3-player-c", cfg)
	base := time.Unix(1700000200, 0).UTC()
	interval := 16 * time.Millisecond
	feedBaseline(t, d, 24, interval, base)

	gapStart := base.Add(24 * interval).Add(350 * time.Millisecond)
	for i := 0; i < 16; i++ {
		seq := uint64(25 + i)
		// Attacker rewrites stamps so their deltas match the 2 ms flush.
		forgedStamp := 24*interval + time.Duration(i+1)*2*time.Millisecond
		res := d.Observe(Packet{
			Seq:         seq,
			RecvAt:      gapStart.Add(time.Duration(i) * 2 * time.Millisecond),
			ClientStamp: forgedStamp,
		})
		if res.Incident != nil && findSignal(res.Incident, "TIMESTAMP_CADENCE_COLLAPSE") != nil {
			if res.Incident.Decision.Primary != ActionFlagReview && res.Incident.Decision.Primary != ActionHoldForReview {
				t.Fatalf("expected review action, got %s", res.Incident.Decision.Primary)
			}
			return
		}
	}
	inc := d.Flush()
	if findSignal(inc, "TIMESTAMP_CADENCE_COLLAPSE") == nil {
		t.Fatalf("expected cadence collapse signal, inc=%+v", inc)
	}
}

func TestNonMonotonicTimestampIsHardReviewEvidence(t *testing.T) {
	d := NewDetector("match-4-player-d", DefaultConfig().WithInputRate(60))
	base := time.Unix(1700000300, 0).UTC()
	feedBaseline(t, d, 18, 16*time.Millisecond, base)

	res := d.Observe(Packet{
		Seq:         19,
		RecvAt:      base.Add(19 * 16 * time.Millisecond),
		ClientStamp: 10 * time.Millisecond, // far before seq 18
	})
	if res.Incident == nil {
		t.Fatal("expected timestamp incident")
	}
	sig := findSignal(res.Incident, "TIMESTAMP_NON_MONOTONIC_BY_SEQ")
	if sig == nil || !sig.Hard {
		t.Fatalf("expected hard non-monotonic signal: %+v", res.Incident.Signals)
	}
	if !res.Incident.Decision.ReviewRequired {
		t.Fatal("hard timestamp evidence must be reviewable")
	}
	if res.Incident.Decision.AutomaticKickAllowed {
		t.Fatal("default policy must not automatically kick")
	}
}

func TestNormalJitterDoesNotOpenIncident(t *testing.T) {
	cfg := DefaultConfig().WithInputRate(60)
	d := NewDetector("match-5-player-e", cfg)
	base := time.Unix(1700000400, 0).UTC()
	seq := uint64(0)
	at := base
	stamp := time.Duration(0)
	jitter := []time.Duration{14, 19, 12, 21, 16, 18, 13, 17}
	for round := 0; round < 20; round++ {
		for _, j := range jitter {
			seq++
			at = at.Add(j * time.Millisecond)
			stamp += 16 * time.Millisecond
			res := d.Observe(Packet{Seq: seq, RecvAt: at, ClientStamp: stamp})
			if res.Incident != nil && res.Incident.Decision.AdjustedScore >= cfg.ReviewScore {
				t.Fatalf("ordinary jitter flagged: %+v", res.Incident)
			}
		}
	}
	if inc := d.Flush(); inc != nil && inc.Decision.AdjustedScore >= cfg.ReviewScore {
		t.Fatalf("ordinary jitter produced review incident: %+v", inc)
	}
}

func BenchmarkObserveNormal60Hz(b *testing.B) {
	d := NewDetector("bench-session", DefaultConfig().WithInputRate(60))
	base := time.Now()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		seq := uint64(i + 1)
		d.Observe(Packet{
			Seq:         seq,
			RecvAt:      base.Add(time.Duration(i) * 16 * time.Millisecond),
			ClientStamp: time.Duration(i+1) * 16 * time.Millisecond,
			Bytes:       64,
		})
	}
}
