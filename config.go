package lagguard

import "time"

// Config controls detection and disposition. The zero value is not usable;
// obtain one from DefaultConfig and adjust for the game's input rate.
type Config struct {
	// ExpectedStampInterval is the game's normal sender/input sample interval.
	// Leave zero to learn a robust median from well-behaved packets.
	ExpectedStampInterval time.Duration

	// StampTolerance absorbs scheduler/clock quantization before a reversed
	// timestamp is treated as anomalous.
	StampTolerance time.Duration

	// GapThreshold is the minimum silence that can begin a hold-and-release
	// episode.
	GapThreshold time.Duration

	// BurstInterPacketGap closes a burst when arrivals become this sparse.
	BurstInterPacketGap time.Duration

	// BurstWindow caps how long one episode may accumulate.
	BurstWindow time.Duration

	// MinBurstPackets avoids accusing a stream after only a few packets.
	MinBurstPackets int

	// MinBurstPPSFactor requires arrival rate to exceed the learned baseline.
	MinBurstPPSFactor float64

	// MinSpanRatio is ClientStamp span / gateway arrival span.
	MinSpanRatio float64

	// MinAccumulatedSpan avoids flagging tiny local bursts with a large ratio.
	MinAccumulatedSpan time.Duration

	// StateChangesPerPacket raises action-density signal above this value.
	StateChangesPerPacket float64

	// RepeatWindow counts prior incidents for escalation.
	RepeatWindow time.Duration

	// Score thresholds.
	ObserveScore int
	ReviewScore  int
	HoldScore    int
	KickScore    int

	// AutomaticKick allows a kick only at KickScore with hard integrity
	// evidence and high confidence. Most operators should leave this false and
	// require referee confirmation for competitive sanctions.
	AutomaticKick bool

	// CellularScorePenalty is subtracted for cellular access because radio
	// scheduling and handovers produce broader benign tails.
	CellularScorePenalty int
}

// DefaultConfig is conservative for 60+ Hz input streams. Games sending at
// 120/240 Hz should lower ExpectedStampInterval and likely GapThreshold.
func DefaultConfig() Config {
	return Config{
		ExpectedStampInterval: 0,
		StampTolerance:        2 * time.Millisecond,

		GapThreshold:        120 * time.Millisecond,
		BurstInterPacketGap: 25 * time.Millisecond,
		BurstWindow:         250 * time.Millisecond,
		MinBurstPackets:     8,
		MinBurstPPSFactor:   3.0,
		MinSpanRatio:        2.5,
		MinAccumulatedSpan:  100 * time.Millisecond,

		StateChangesPerPacket: 1.2,
		RepeatWindow:          10 * time.Minute,

		ObserveScore: 30,
		ReviewScore:  48,
		HoldScore:    72,
		KickScore:    90,

		AutomaticKick:        false,
		CellularScorePenalty: 6,
	}
}

// WithInputRate returns a config tuned for a nominal input rate in Hz.
func (c Config) WithInputRate(hz int) Config {
	if hz <= 0 {
		return c
	}
	c.ExpectedStampInterval = time.Second / time.Duration(hz)
	// A gap is roughly seven missed input opportunities, bounded to sane values.
	gap := 7 * c.ExpectedStampInterval
	if gap < 80*time.Millisecond {
		gap = 80 * time.Millisecond
	}
	if gap > 180*time.Millisecond {
		gap = 180 * time.Millisecond
	}
	c.GapThreshold = gap
	c.MinAccumulatedSpan = gap - 20*time.Millisecond
	c.BurstInterPacketGap = 2 * c.ExpectedStampInterval
	if c.BurstInterPacketGap < 12*time.Millisecond {
		c.BurstInterPacketGap = 12 * time.Millisecond
	}
	return c
}
