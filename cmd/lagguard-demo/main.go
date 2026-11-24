package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	lagguard "lagguard"
)

func main() {
	out := flag.String("out", "examples/hold-release-review-bundle.json", "path to write signed review bundle")
	flag.Parse()

	if err := run(*out); err != nil {
		fmt.Fprintf(os.Stderr, "demo failed: %v\n", err)
		os.Exit(1)
	}
}

func run(outPath string) error {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return err
	}

	cfg := lagguard.DefaultConfig().WithInputRate(60)
	started := time.Unix(1764000000, 0).UTC()
	ctx := lagguard.ReviewContext{
		SessionID:       "demo-session-0001",
		MatchID:         "demo-match-7788",
		StreamID:        "input-uplink-0",
		GameID:          "demo-fighter",
		PlayerPseudonym: "player-pseud-42",
		DetectorVersion: "lagguard-demo/v0.1.0",
		StartedAt:       started,
		Config:          cfg,
	}
	journal, err := lagguard.NewJournal(ctx, key, nil)
	if err != nil {
		return err
	}
	gate := &lagguard.Gate{
		Detector: lagguard.NewDetector(ctx.SessionID, cfg),
		Recorder: journal,
		OnDecision: func(d lagguard.Decision, inc *lagguard.Incident) {
			fmt.Printf("incident=%s score=%d adjusted=%d network=%s action=%s review=%v\n",
				inc.ID, d.Score, d.AdjustedScore, d.NetworkEvidenceLevel, d.Primary, d.ReviewRequired)
		},
		OnError: func(err error) {
			fmt.Fprintf(os.Stderr, "evidence error: %v\n", err)
		},
	}

	// Normal 60 Hz baseline.
	interval := 16 * time.Millisecond
	for seq := uint64(1); seq <= 24; seq++ {
		gate.Observe(lagguard.Packet{
			Seq:          seq,
			RecvAt:       started.Add(time.Duration(seq) * interval),
			ClientStamp:  time.Duration(seq) * interval,
			StateChanges: 1,
		})
	}

	// Healthy RTT telemetry makes the later absence of loss/RTT inflation meaningful.
	gate.Detector.ObserveNetwork(lagguard.NetworkReport{
		At:       started.Add(24 * interval),
		RTT:      24 * time.Millisecond,
		Jitter:   3 * time.Millisecond,
		Access:   lagguard.AccessWiFi,
		LossRate: 0.001,
	})

	// 420 ms uplink hold, then 16 packets flushed at roughly 2 ms intervals.
	// A companion RTCP/keepalive response survives the gap, making this look
	// selective rather than a complete access-network outage.
	burstStart := started.Add(24 * interval).Add(420 * time.Millisecond)
	for i := 0; i < 16; i++ {
		seq := uint64(25 + i)
		pkt := lagguard.Packet{
			Seq:          seq,
			RecvAt:       burstStart.Add(time.Duration(i) * 2 * time.Millisecond),
			ClientStamp:  time.Duration(seq) * interval,
			StateChanges: 2,
			ActionEvents: 0,
		}
		if i == 0 {
			pkt.CompanionPacketsInGap = 2
			pkt.ProbesSentInGap = 2
			pkt.ProbeResponsesInGap = 1
			pkt.OpponentFrameGap = 410 * time.Millisecond
			pkt.ServerTickGap = 420 * time.Millisecond
			pkt.RollbackEvents = 14
		}
		gate.Observe(pkt)
	}
	gate.Flush()

	bundle, err := journal.Finalize(started.Add(2 * time.Minute))
	if err != nil {
		return err
	}
	if err := bundle.Verify(); err != nil {
		return fmt.Errorf("self-verification: %w", err)
	}

	if dir := filepath.Dir(outPath); dir != "." && dir != "" {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	f, err := os.Create(outPath)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := bundle.WriteJSON(f); err != nil {
		return err
	}

	fmt.Printf("\nwrote %s\n", outPath)
	fmt.Printf("events=%d root=%s\n", bundle.EventCount, bundle.RootHash[0:16]+"…")
	fmt.Printf("signer fingerprint (pin this in referee backend): %s\n", bundle.SignerFingerprint)
	fmt.Printf("embedded public key: %s\n", encodeKey(pub))
	return nil
}

func encodeKey(k ed25519.PublicKey) string {
	b, _ := json.Marshal(k)
	return string(b)
}
