package lagguard

import "time"

// AccessNetwork describes the player's access link class. It is context, not
// proof of wrongdoing.
type AccessNetwork string

const (
	AccessUnknown  AccessNetwork = "unknown"
	AccessWired    AccessNetwork = "wired"
	AccessWiFi     AccessNetwork = "wifi"
	AccessCellular AccessNetwork = "cellular"
)

// Packet is the gateway's passive metadata view of one input packet.
//
// RecvAt must be read from the gateway's monotonic clock immediately on receipt.
// ClientStamp is the sender timestamp after decoding its unit/epoch; the
// detector never trusts it for scheduling.
type Packet struct {
	Seq         uint64
	RecvAt      time.Time
	ClientStamp time.Duration

	// Input semantics are optional but materially improve detection. They can
	// be populated after parsing the already-forwarded payload.
	Samples      int // input samples represented by this packet
	StateChanges int // changed controls/axes relative to the previous sample
	ActionEvents int // discrete high-intent events: fire, cast, item use, etc.
	Bytes        int

	// Network recovery metadata.
	IsRetransmission bool
	FECRecovered     bool

	// Independent channel evidence for the interval since the previous input.
	// These fields only need to be populated on the first packet after a gap.
	CompanionPacketsInGap int // audio/RTCP/keepalive packets received
	ProbesSentInGap       int
	ProbeResponsesInGap   int

	// Match-plane correlation. The gateway can join the attacker's burst with
	// the opponent's downstream frame gap or server rollback/tick stall. These
	// are usually populated only for the packet that closes a suspected gap.
	OpponentFrameGap time.Duration
	ServerTickGap    time.Duration
	RollbackEvents   int
}

// NetworkReport is periodic transport/network telemetry. Rates are expected in
// [0,1].
type NetworkReport struct {
	At              time.Time
	RTT             time.Duration
	Jitter          time.Duration
	LossRate        float64
	Retransmissions int
	FECRecovered    int
	Access          AccessNetwork
	Handover        bool

	// AllUplinkFlowsImpaired should be set when gateway/RTCP telemetry shows
	// audio, control and input channels were impaired together.
	AllUplinkFlowsImpaired bool
}

// Signal is one transparent, reviewable scoring reason.
type Signal struct {
	Code       string             `json:"code"`
	Title      string             `json:"title"`
	Detail     string             `json:"detail"`
	Points     int                `json:"points"`
	Hard       bool               `json:"hard,omitempty"`
	Exonerator bool               `json:"exonerator,omitempty"`
	Data       map[string]float64 `json:"data,omitempty"`
	Seqs       []uint64           `json:"seqs,omitempty"`
}

// Action is the policy action selected by the detector.
type Action string

const (
	ActionPass            Action = "pass"
	ActionObserve         Action = "observe"
	ActionEnhancedCapture Action = "enhanced_capture"
	ActionFlagReview      Action = "flag_for_human_review"
	ActionNormalizeBurst  Action = "normalize_burst"
	ActionHoldForReview   Action = "hold_competitive_input"
	ActionSuspend         Action = "temporary_suspension"
	ActionKick            Action = "kick"
)

// Decision is the policy outcome for an incident.
type Decision struct {
	Primary              Action   `json:"primary"`
	Actions              []Action `json:"actions,omitempty"`
	Score                int      `json:"score"`
	AdjustedScore        int      `json:"adjusted_score"`
	Confidence           float64  `json:"confidence"`
	NetworkEvidenceLevel string   `json:"network_evidence_level"`
	ReasonCodes          []string `json:"reason_codes,omitempty"`
	ReviewRequired       bool     `json:"review_required"`
	AutomaticKickAllowed bool     `json:"automatic_kick_allowed"`
	Message              string   `json:"message,omitempty"`
}

// Incident captures one gap-then-release episode and its scoring rationale.
type Incident struct {
	ID        string    `json:"id"`
	SessionID string    `json:"session_id"`
	StartedAt time.Time `json:"started_at"`
	EndedAt   time.Time `json:"ended_at"`
	Complete  bool      `json:"complete"`

	SeqBeforeGap uint64 `json:"seq_before_gap"`
	FirstSeq     uint64 `json:"first_seq"`
	LastSeq      uint64 `json:"last_seq"`
	MinSeq       uint64 `json:"min_seq"`
	MaxSeq       uint64 `json:"max_seq"`
	PacketCount  int    `json:"packet_count"`
	MissingSeqs  int    `json:"missing_seqs"`
	OutOfOrder   bool   `json:"out_of_order"`

	ArrivalGap      time.Duration `json:"arrival_gap"`
	BurstDuration   time.Duration `json:"burst_duration"`
	StampSpan       time.Duration `json:"stamp_span"`
	SpanRatio       float64       `json:"span_ratio"`
	ArrivalsPerSec  float64       `json:"arrivals_per_sec"`
	BaselinePPS     float64       `json:"baseline_pps"`
	BurstPPSFactor  float64       `json:"burst_pps_factor"`
	Samples         int           `json:"samples"`
	StateChanges    int           `json:"state_changes"`
	ActionEvents    int           `json:"action_events"`
	Retransmissions int           `json:"retransmissions"`
	FECRecovered    int           `json:"fec_recovered"`

	OpponentFrameGap time.Duration `json:"opponent_frame_gap"`
	ServerTickGap    time.Duration `json:"server_tick_gap"`
	RollbackEvents   int           `json:"rollback_events"`

	RepeatedCount int `json:"repeated_count"`

	Signals  []Signal `json:"signals"`
	Decision Decision `json:"decision"`
}

// Metrics is a small point-in-time view for operations dashboards.
type Metrics struct {
	PacketsObserved  uint64        `json:"packets_observed"`
	Incidents        int           `json:"incidents"`
	BaselineInterval time.Duration `json:"baseline_interval_ns"`
	BaselinePPS      float64       `json:"baseline_pps"`
	BaselineRTT      time.Duration `json:"baseline_rtt_ns"`
	RecentLossRate   float64       `json:"recent_loss_rate"`
	Access           AccessNetwork `json:"access"`
}

// Result is returned for every observed packet. Incident is non-nil when the
// call created or materially updated an incident. Incidents can contain both a
// just-completed burst and a separate timestamp incident on the same call.
type Result struct {
	Incident  *Incident   `json:"incident,omitempty"`
	Incidents []*Incident `json:"incidents,omitempty"`
	Decision  Decision    `json:"decision"`
	Metrics   Metrics     `json:"metrics"`
}
