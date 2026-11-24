package lagguard

import (
	"math"
	"time"
)

func (d *Detector) decide(inc *Incident) Decision {
	cfg := d.cfg
	hardPoints := 0
	behaviorPoints := 0
	exoneration := 0
	reasons := make([]string, 0, len(inc.Signals)+1)
	hasHard := false
	for _, s := range inc.Signals {
		reasons = append(reasons, s.Code)
		switch {
		case s.Exonerator:
			exoneration += s.Points
		case s.Hard:
			hardPoints += s.Points
			hasHard = true
		default:
			behaviorPoints += s.Points
		}
	}

	raw := clampInt(hardPoints+behaviorPoints, 0, 100)
	behaviorAdjusted := maxInt(0, behaviorPoints-exoneration)
	if d.access == AccessCellular {
		behaviorAdjusted = maxInt(0, behaviorAdjusted-cfg.CellularScorePenalty)
		reasons = append(reasons, "CELLULAR_UNCERTAINTY_PENALTY")
	}
	// Network evidence can explain shape/jitter, but cannot erase a deterministic
	// sequence/timestamp contradiction.
	score := raw
	adjusted := clampInt(hardPoints+behaviorAdjusted, 0, 100)

	level := networkEvidenceLevel(inc.Signals)
	confidence := d.confidence(inc)
	kickAllowed := cfg.AutomaticKick &&
		adjusted >= cfg.KickScore &&
		hasHard &&
		confidence >= 0.9 &&
		level == EvidenceNone

	decision := Decision{
		Score:                score,
		AdjustedScore:        adjusted,
		Confidence:           math.Round(confidence*100) / 100,
		NetworkEvidenceLevel: level,
		ReasonCodes:          reasons,
		ReviewRequired:       adjusted >= cfg.ReviewScore || hasHard,
		AutomaticKickAllowed: kickAllowed,
	}

	switch {
	case kickAllowed:
		decision.Primary = ActionKick
		decision.Actions = []Action{ActionEnhancedCapture, ActionFlagReview, ActionKick}
		decision.Message = "硬证据达到自动断开阈值；仍需生成签名证据供裁判复核。"

	case adjusted >= cfg.HoldScore && confidence >= 0.6 && level != EvidenceStrong:
		decision.Primary = ActionHoldForReview
		decision.Actions = []Action{ActionEnhancedCapture, ActionNormalizeBurst, ActionFlagReview, ActionHoldForReview}
		decision.ReviewRequired = true
		decision.Message = "高置信疑似操纵：可规范化后续突发输入并冻结排位结果，提交裁判复核；默认不直接踢出。"

	case adjusted >= cfg.ReviewScore || (hasHard && adjusted >= cfg.ObserveScore):
		decision.Primary = ActionFlagReview
		decision.Actions = []Action{ActionEnhancedCapture, ActionFlagReview}
		decision.ReviewRequired = true
		decision.Message = "存在可复核异常或硬完整性信号：加强取证并标记裁判复核，不直接影响当前对局。"

	case adjusted >= cfg.ObserveScore:
		decision.Primary = ActionEnhancedCapture
		decision.Actions = []Action{ActionObserve, ActionEnhancedCapture}
		decision.Message = "弱信号或被网络证据部分解释：仅扩大遥测，不处罚。"

	default:
		decision.Primary = ActionPass
		decision.Actions = []Action{ActionPass}
		decision.ReviewRequired = false
		decision.Message = "未达到干预阈值。"
	}

	// Strong external network evidence overrides punitive action even when raw
	// arrival shape looks suspicious. Referees still see every signal.
	if level == EvidenceStrong && !hasHard && decision.Primary != ActionPass {
		decision.Primary = ActionObserve
		decision.Actions = []Action{ActionObserve, ActionEnhancedCapture}
		decision.ReviewRequired = false
		decision.AutomaticKickAllowed = false
		decision.Message = "强真实网络故障旁证：按弱网抖动处理并优化抖动缓冲，不进入处罚流程。"
	}
	return decision
}

const (
	EvidenceNone   = "none"
	EvidenceWeak   = "weak"
	EvidenceStrong = "strong"
)

func networkEvidenceLevel(signals []Signal) string {
	strongHits := 0
	weakHits := 0
	for _, s := range signals {
		if !s.Exonerator {
			continue
		}
		strong := false
		switch s.Code {
		case "REAL_NETWORK_SEQUENCE_LOSS":
			strong = s.Points >= 24
		case "RECENT_HIGH_PACKET_LOSS":
			strong = s.Points >= 24
		case "ACCESS_HANDOVER", "ALL_UPLINK_FLOWS_IMPAIRED":
			strong = true
		}
		if strong {
			strongHits++
		} else {
			weakHits++
		}
	}
	if strongHits >= 2 || (strongHits >= 1 && weakHits >= 1) {
		return EvidenceStrong
	}
	if strongHits == 1 || weakHits > 0 {
		return EvidenceWeak
	}
	return EvidenceNone
}

func (d *Detector) confidence(inc *Incident) float64 {
	c := 0.35
	if inc.PacketCount >= d.cfg.MinBurstPackets {
		c += 0.18
	}
	if inc.PacketCount >= 20 {
		c += 0.1
	}
	if d.stampIntervals.len() >= 12 || d.arrivalIntervals.len() >= 12 {
		c += 0.15
	}
	if d.haveReport {
		delta := d.lastObservedAt.Sub(d.lastReportAt)
		if delta < 0 {
			delta = -delta
		}
		if delta <= 30*time.Second {
			c += 0.1
		}
	}
	if inc.Samples > 0 || inc.StateChanges > 0 || inc.ActionEvents > 0 {
		c += 0.05
	}
	for _, s := range inc.Signals {
		if s.Hard {
			c += 0.18
			break
		}
	}
	if d.access == AccessCellular {
		c -= 0.05
	}
	return clamp01(c)
}
