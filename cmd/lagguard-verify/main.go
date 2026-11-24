package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	lagguard "lagguard"
)

func main() {
	bundlePath := flag.String("bundle", "", "path to ReviewBundle JSON")
	flag.Parse()
	if *bundlePath == "" {
		fmt.Fprintln(os.Stderr, "usage: lagguard-verify -bundle <file.json>")
		os.Exit(2)
	}
	if err := verify(*bundlePath); err != nil {
		fmt.Fprintf(os.Stderr, "INVALID: %v\n", err)
		os.Exit(1)
	}
	fmt.Println("OK: hash chain and Ed25519 signature are valid")
}

func verify(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var bundle lagguard.ReviewBundle
	if err := json.Unmarshal(data, &bundle); err != nil {
		return fmt.Errorf("parse bundle: %w", err)
	}
	if err := bundle.Verify(); err != nil {
		return err
	}

	fmt.Printf("session: %s\n", bundle.Context.SessionID)
	fmt.Printf("match: %s\n", bundle.Context.MatchID)
	fmt.Printf("player pseudonym: %s\n", bundle.Context.PlayerPseudonym)
	fmt.Printf("events: %d\n", bundle.EventCount)
	fmt.Printf("root hash: %s\n", bundle.RootHash)
	fmt.Printf("signer fingerprint: %s\n", bundle.SignerFingerprint)
	fmt.Println("incidents:")
	for _, event := range bundle.Events {
		inc := event.Incident
		if inc == nil {
			continue
		}
		fmt.Printf("  - seq=%d id=%s complete=%v score=%d adjusted=%d action=%s network=%s\n",
			event.Sequence, inc.ID, inc.Complete, inc.Decision.Score, inc.Decision.AdjustedScore,
			inc.Decision.Primary, inc.Decision.NetworkEvidenceLevel)
		for _, sig := range inc.Signals {
			kind := "signal"
			if sig.Exonerator {
				kind = "network"
			} else if sig.Hard {
				kind = "hard"
			}
			fmt.Printf("      [%s] %s (%+d) %s\n", kind, sig.Code, signedPoints(sig), sig.Title)
		}
	}
	fmt.Println("\nRemember: verification proves integrity and signer possession, not signer trust.")
	fmt.Println("Pin the fingerprint above in the referee backend.")
	return nil
}

func signedPoints(s lagguard.Signal) int {
	if s.Exonerator {
		return -s.Points
	}
	return s.Points
}
