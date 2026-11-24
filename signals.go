package lagguard

import (
	"sort"
	"time"
)

func (d *Detector) buildBurstIncident(complete bool) *Incident {
	d.refreshBaselines()
	b := &d.burst
	d.incidentSeq++
	id := b.id
	if id == "" {
		id = d.sessionID + "-burst-" + itoaUint64(d.incidentSeq) + "-" + itoaInt64(int64(b.firstStamp/time.Millisecond))
	}

	burstDuration := b.last.Sub(b.start)
	stampSpan := b.lastStamp - b.firstStamp
	var ratio float64
	if burstDuration > 0 {
		ratio = float64(stampSpan) / float64(burstDuration)
	}
	pps := 0.0
	if burstDuration > 0 && b.count > 1 {
		pps = float64(b.count-1) / burstDuration.Seconds()
	}
	baselinePPS := d.baselinePPS
	ppsFactor := 0.0
	if baselinePPS > 0 {
		ppsFactor = pps / baselinePPS
	}

	missing := 0
	if b.haveMinMax {
		switch {
		case b.seqBefore > 0 && b.maxSeq > b.seqBefore:
			// Expected new sequence numbers are seqBefore+1..maxSeq. Count
			// only observed unique sequences inside that range.
			expected := int64(b.maxSeq - b.seqBefore)
			observed := 0
			for seq := range b.seen {
				if seq > b.seqBefore && seq <= b.maxSeq {
					observed++
				}
			}
			missing = int(clamp(float64(expected-int64(observed)), 0, float64(expected)))
		case b.maxSeq >= b.minSeq:
			span := int64(b.maxSeq-b.minSeq) + 1
			unique := len(b.seen)
			if span > int64(unique) {
				missing = int(span - int64(unique))
			}
		}
	}

	repeatCount := d.recentIncidentCount(b.start)
	if !b.opened {
		repeatCount++
	}

	inc := &Incident{
		ID:              id,
		SessionID:       d.sessionID,
		StartedAt:       b.start,
		EndedAt:         b.last,
		Complete:        complete,
		SeqBeforeGap:    b.seqBefore,
		FirstSeq:        b.firstSeq,
		LastSeq:         b.lastArrivalSeq,
		MinSeq:          b.minSeq,
		MaxSeq:          b.maxSeq,
		PacketCount:     b.count,
		MissingSeqs:     missing,
		OutOfOrder:      b.outOfOrder,
		ArrivalGap:      b.triggerGap,
		BurstDuration:   burstDuration,
		StampSpan:       stampSpan,
		SpanRatio:       ratio,
		ArrivalsPerSec:  pps,
		BaselinePPS:     baselinePPS,
		BurstPPSFactor:  ppsFactor,
		Samples:         b.samples,
		StateChanges:    b.changes,
		ActionEvents:    b.actions,
		Retransmissions: b.retrans,
		FECRecovered:    b.fec,

		OpponentFrameGap: b.opponentFrameGap,
		ServerTickGap:    b.serverTickGap,
		RollbackEvents:   b.rollbackEvents,

		RepeatedCount: repeatCount,
		Signals:       append([]Signal(nil), b.signals...),
	}

	d.addBurstSignals(inc, b)
	d.addCadenceSignal(inc, b)
	d.addNetworkExonerators(inc)
	inc.Decision = d.decide(inc)
	return inc
}

func (d *Detector) addBurstSignals(inc *Incident, b *burstState) {
	if inc.ArrivalGap >= d.cfg.GapThreshold &&
		inc.PacketCount >= d.cfg.MinBurstPackets &&
		(inc.BurstPPSFactor >= d.cfg.MinBurstPPSFactor || inc.ArrivalsPerSec >= 100) {
		inc.Signals = append(inc.Signals, Signal{
			Code:   "ARRIVAL_GAP_THEN_PACKET_BURST",
			Title:  "长静默后出现补偿性突发",
			Detail: "网关先观测到超过阈值的上行空档，随后在极短时间内收到大量输入包。",
			Points: 18,
			Data: map[string]float64{
				"gap_ms":           float64(inc.ArrivalGap.Milliseconds()),
				"burst_ms":         float64(inc.BurstDuration.Milliseconds()),
				"pps":              inc.ArrivalsPerSec,
				"pps_factor":       inc.BurstPPSFactor,
				"packet_count":     float64(inc.PacketCount),
				"threshold_gap_ms": float64(d.cfg.GapThreshold.Milliseconds()),
			},
			Seqs: seqRange(inc.MinSeq, inc.MaxSeq, 12),
		})
	}

	if inc.StampSpan >= d.cfg.MinAccumulatedSpan && inc.SpanRatio >= d.cfg.MinSpanRatio {
		points := 20
		if inc.SpanRatio >= 6 {
			points = 30
		} else if inc.SpanRatio >= 4 {
			points = 25
		}
		inc.Signals = append(inc.Signals, Signal{
			Code:   "TIME_COMPRESSION_BURST",
			Title:  "输入时间跨度被突发到达时间压缩",
			Detail: "客户端时间戳显示输入在空档期间持续产生，但网关到达间隔极短，符合“先积攒、后一次性放行”。",
			Points: points,
			Data: map[string]float64{
				"stamp_span_ms":   float64(inc.StampSpan.Milliseconds()),
				"arrival_span_ms": float64(inc.BurstDuration.Milliseconds()),
				"ratio":           inc.SpanRatio,
			},
			Seqs: seqRange(inc.MinSeq, inc.MaxSeq, 12),
		})
	}

	if inc.MissingSeqs == 0 && inc.ArrivalGap >= d.cfg.GapThreshold && inc.PacketCount >= d.cfg.MinBurstPackets {
		inc.Signals = append(inc.Signals, Signal{
			Code:   "CONTIGUOUS_SEQUENCE_RELEASE",
			Title:  "空档前后序列号连续且整段放行",
			Detail: "空档没有造成序列号缺口或重传/FEC恢复。家庭网络真实中断通常会留下缺口、重传或带宽恢复信号；但运营商缓冲也可能产生此现象，因此不能单独定性。",
			Points: 9,
			Data:   map[string]float64{"missing_seqs": 0},
		})
	}

	if float64(inc.StateChanges) >= float64(inc.PacketCount)*d.cfg.StateChangesPerPacket || inc.ActionEvents >= 5 {
		inc.Signals = append(inc.Signals, Signal{
			Code:   "HIGH_ACTION_DENSITY_IN_BURST",
			Title:  "突发中操作密度异常高",
			Detail: "短时间涌入大量控制变更或高意图操作事件，可能让服务器单个 tick 处理积攒指令。",
			Points: 12,
			Data: map[string]float64{
				"state_changes": float64(inc.StateChanges),
				"action_events": float64(inc.ActionEvents),
				"packets":       float64(inc.PacketCount),
			},
		})
	}

	if inc.ArrivalGap >= d.cfg.GapThreshold && (b.probesReply > 0 || b.companion > 0) {
		inc.Signals = append(inc.Signals, Signal{
			Code:   "SELECTIVE_INPUT_GAP_WITH_LIVE_CHANNEL",
			Title:  "输入中断期间其他上行/探测通道仍存活",
			Detail: "网关在同一空档收到伴流包或收到探测响应，说明接入网并未完全中断，输入链路可能被选择性延迟或在终端本地排队。",
			Points: 24,
			Data: map[string]float64{
				"companion_packets": float64(b.companion),
				"probe_replies":     float64(b.probesReply),
				"probes_sent":       float64(b.probesSent),
			},
		})
	}

	if inc.OpponentFrameGap >= 120*time.Millisecond || inc.ServerTickGap >= 120*time.Millisecond || inc.RollbackEvents >= 8 {
		inc.Signals = append(inc.Signals, Signal{
			Code:   "OPPONENT_STALL_TEMPORALLY_CORRELATED",
			Title:  "对手画面/服务器 tick 卡顿与输入突发时间相关",
			Detail: "对局总线或下游串流遥测显示：攻击者上行空档期间，对手下游帧间隔、服务器 tick 或回滚次数异常，并在输入突发到达后恢复。该跨玩家相关性比单流抖动更接近利用效果。",
			Points: 18,
			Data: map[string]float64{
				"opponent_frame_gap_ms": float64(inc.OpponentFrameGap.Milliseconds()),
				"server_tick_gap_ms":    float64(inc.ServerTickGap.Milliseconds()),
				"rollback_events":       float64(inc.RollbackEvents),
			},
		})
	}

	if inc.RepeatedCount >= 2 {
		points := 8 * (inc.RepeatedCount - 1)
		if points > 24 {
			points = 24
		}
		inc.Signals = append(inc.Signals, Signal{
			Code:   "REPEATED_GAP_RELEASE_PATTERN",
			Title:  "时间窗内重复出现相同模式",
			Detail: "单次缓冲可能来自网络，但反复在对战关键时刻出现长静默后补偿突发，故意操纵的可能性显著提高。",
			Points: points,
			Data:   map[string]float64{"repeat_count": float64(inc.RepeatedCount)},
		})
	}
}

func (d *Detector) addCadenceSignal(inc *Incident, b *burstState) {
	baseline := d.baselineStampInterval()
	if baseline <= 0 || len(b.stampDeltas) < 5 {
		return
	}
	seconds := make([]float64, 0, len(b.stampDeltas))
	for _, delta := range b.stampDeltas {
		if delta > 0 {
			seconds = append(seconds, delta.Seconds())
		}
	}
	if len(seconds) < 5 {
		return
	}
	sort.Float64s(seconds)
	medianDelta := time.Duration(seconds[len(seconds)/2] * float64(time.Second))
	if medianDelta > 0 && medianDelta < time.Duration(float64(baseline)*0.45) {
		inc.Signals = append(inc.Signals, Signal{
			Code:   "TIMESTAMP_CADENCE_COLLAPSE",
			Title:  "突发内时间戳节拍相对正常采样率异常压缩",
			Detail: "真实网络抖动不会改变客户端按固定采样周期生成的时间戳；若伪造者把时间戳改写成突发到达间隔，突发内时间戳中位数会显著小于学习到的正常采样周期。",
			Points: 28,
			Data: map[string]float64{
				"burst_stamp_median_ms": float64(medianDelta.Microseconds()) / 1000,
				"baseline_interval_ms":  float64(baseline.Microseconds()) / 1000,
				"ratio":                 float64(medianDelta) / float64(baseline),
			},
			Seqs: seqRange(inc.MinSeq, inc.MaxSeq, 12),
		})
	}
}

func (d *Detector) addNetworkExonerators(inc *Incident) {
	span := inc.MaxSeq - inc.MinSeq + 1
	missingRatio := 0.0
	if span > 0 && inc.MaxSeq >= inc.MinSeq {
		missingRatio = float64(inc.MissingSeqs) / float64(span)
	}
	if inc.MissingSeqs >= 2 && missingRatio >= 0.15 {
		inc.Signals = append(inc.Signals, Signal{
			Code:       "REAL_NETWORK_SEQUENCE_LOSS",
			Title:      "空档伴随明显序列号缺口",
			Detail:     "突发前后存在大量未到达序列号，更符合真实丢包/中断后的恢复，而不是完整缓存后放行。",
			Points:     26,
			Exonerator: true,
			Data: map[string]float64{
				"missing_seqs":  float64(inc.MissingSeqs),
				"missing_ratio": missingRatio,
			},
		})
	}

	recovery := inc.Retransmissions + inc.FECRecovered
	reportRecovery := 0
	if d.haveReport {
		reportRecovery = d.networkReport.Retransmissions + d.networkReport.FECRecovered
	}
	if recovery >= 2 || reportRecovery >= 2 {
		inc.Signals = append(inc.Signals, Signal{
			Code:       "REAL_NETWORK_RECOVERY_OBSERVED",
			Title:      "观测到重传或FEC恢复",
			Detail:     "传输层恢复机制在同一时段工作，是真实丢包和抖动的有力旁证。",
			Points:     18,
			Exonerator: true,
			Data: map[string]float64{
				"burst_recovery":  float64(recovery),
				"report_recovery": float64(reportRecovery),
			},
		})
	}

	if d.lossRate >= 0.05 {
		points := 18
		if d.lossRate >= 0.15 {
			points = 28
		}
		inc.Signals = append(inc.Signals, Signal{
			Code:       "RECENT_HIGH_PACKET_LOSS",
			Title:      "近期网络丢包率较高",
			Detail:     "RTCP/传输遥测显示该玩家链路存在真实丢包；统计异常应优先按弱网处理。",
			Points:     points,
			Exonerator: true,
			Data:       map[string]float64{"loss_rate": d.lossRate},
		})
	}

	if d.baselineRTT > 0 && d.haveReport && d.networkReport.RTT > 0 {
		rttRatio := float64(d.networkReport.RTT) / float64(d.baselineRTT)
		if rttRatio >= 1.8 && d.networkReport.RTT-d.baselineRTT >= 30*time.Millisecond {
			inc.Signals = append(inc.Signals, Signal{
				Code:       "RTT_INFLATION_DURING_EPISODE",
				Title:      "RTT相对基线明显膨胀",
				Detail:     "空档附近RTT升高，符合家庭宽带缓冲膨胀或移动网络调度抖动。",
				Points:     16,
				Exonerator: true,
				Data: map[string]float64{
					"rtt_ms":          float64(d.networkReport.RTT.Milliseconds()),
					"baseline_rtt_ms": float64(d.baselineRTT.Milliseconds()),
					"ratio":           rttRatio,
				},
			})
		}
	}

	if d.haveReport && d.networkReport.Handover {
		inc.Signals = append(inc.Signals, Signal{
			Code:       "ACCESS_HANDOVER",
			Title:      "发生Wi-Fi/蜂窝或基站切换",
			Detail:     "接入网切换可造成数百毫秒上行中断和恢复突发，不应据此处罚玩家。",
			Points:     18,
			Exonerator: true,
		})
	}
	if d.haveReport && d.networkReport.AllUplinkFlowsImpaired {
		inc.Signals = append(inc.Signals, Signal{
			Code:       "ALL_UPLINK_FLOWS_IMPAIRED",
			Title:      "所有上行流同时受损",
			Detail:     "音频、控制、输入等多条流同步出现损伤，更符合接入网故障而非针对输入时序的操纵。",
			Points:     20,
			Exonerator: true,
		})
	}
}

func itoaUint64(v uint64) string {
	if v == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for v > 0 {
		i--
		buf[i] = byte('0' + v%10)
		v /= 10
	}
	return string(buf[i:])
}

func itoaInt64(v int64) string {
	if v == 0 {
		return "0"
	}
	neg := v < 0
	if neg {
		v = -v
	}
	s := itoaUint64(uint64(v))
	if neg {
		return "-" + s
	}
	return s
}
