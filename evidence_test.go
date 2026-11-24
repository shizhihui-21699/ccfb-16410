package lagguard

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"
)

func TestReviewBundleHashChainAndSignature(t *testing.T) {
	pub, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var jsonl bytes.Buffer
	j, err := NewJournal(ReviewContext{
		SessionID:       "sess-1",
		MatchID:         "match-1",
		PlayerPseudonym: "pseud-abc",
		Config:          DefaultConfig().WithInputRate(60),
		StartedAt:       time.Unix(1700000000, 0).UTC(),
	}, key, &jsonl)
	if err != nil {
		t.Fatal(err)
	}

	inc := &Incident{ID: "inc-1", SessionID: "sess-1", Complete: true}
	if err := j.Record(inc); err != nil {
		t.Fatal(err)
	}
	inc2 := *inc
	inc2.ID = "inc-2"
	if err := j.Record(&inc2); err != nil {
		t.Fatal(err)
	}

	bundle, err := j.Finalize(time.Unix(1700000100, 0).UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := bundle.Verify(); err != nil {
		t.Fatalf("valid bundle failed verification: %v", err)
	}
	if bundle.SignerFingerprint == "" || len(bundle.Signature) != ed25519.SignatureSize {
		t.Fatal("bundle missing signature material")
	}
	if !bytes.Equal(bundle.PublicKey, pub) {
		t.Fatal("unexpected public key")
	}
	if jsonl.Len() == 0 {
		t.Fatal("expected JSONL events to be written")
	}

	// Tampering with any incident field must break the hash chain.
	bundle.Events[0].Incident.ID = "tampered"
	if err := bundle.Verify(); err == nil {
		t.Fatal("tampered bundle unexpectedly verified")
	}
}

func TestAsyncRecorderDoesNotBlockAndQueues(t *testing.T) {
	j, err := NewJournal(ReviewContext{SessionID: "async"}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	a := NewAsyncRecorder(j, 4)
	for i := 0; i < 12; i++ {
		_ = a.Record(&Incident{ID: "x"}) // either queued or shed without blocking
	}
	if err := a.Close(); err != nil {
		t.Fatal(err)
	}
	bundle, err := j.Finalize(time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if bundle.EventCount == 0 {
		t.Fatal("expected at least some queued events")
	}
	if bundle.EventCount > 12 {
		t.Fatalf("unexpected event count %d", bundle.EventCount)
	}
}
