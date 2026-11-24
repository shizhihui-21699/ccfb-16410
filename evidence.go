package lagguard

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"
)

const SchemaVersion = "lagguard-evidence/v1"

// ReviewContext identifies a match/session and the detector configuration that
// produced evidence. Pseudonyms should be used instead of account names where
// possible.
type ReviewContext struct {
	SchemaVersion   string    `json:"schema_version"`
	SessionID       string    `json:"session_id"`
	MatchID         string    `json:"match_id,omitempty"`
	StreamID        string    `json:"stream_id,omitempty"`
	GameID          string    `json:"game_id,omitempty"`
	PlayerPseudonym string    `json:"player_pseudonym,omitempty"`
	DetectorVersion string    `json:"detector_version"`
	StartedAt       time.Time `json:"started_at"`
	Config          Config    `json:"config"`
}

// EvidenceEvent is one hash-chained incident version.
type EvidenceEvent struct {
	SchemaVersion string    `json:"schema_version"`
	Sequence      uint64    `json:"sequence"`
	RecordedAt    time.Time `json:"recorded_at"`
	Incident      *Incident `json:"incident"`
	PrevHash      string    `json:"prev_hash"`
	Hash          string    `json:"hash"`
}

// ReviewBundle is the signed artifact given to referees. The public key is
// embedded for offline verification, but the referee service must pin/trusted
// signer fingerprints to establish provenance.
type ReviewBundle struct {
	SchemaVersion     string            `json:"schema_version"`
	Context           ReviewContext     `json:"context"`
	Events            []EvidenceEvent   `json:"events"`
	EventCount        int               `json:"event_count"`
	RootHash          string            `json:"root_hash"`
	PublicKey         ed25519.PublicKey `json:"public_key"`
	SignerFingerprint string            `json:"signer_fingerprint"`
	Signature         []byte            `json:"signature"`
	SignedAt          time.Time         `json:"signed_at"`
}

// Recorder receives incidents from the gateway fast path.
type Recorder interface {
	Record(*Incident) error
}

// Journal is an append-only hash chain and signable review bundle.
type Journal struct {
	mu     sync.Mutex
	ctx    ReviewContext
	key    ed25519.PrivateKey
	out    io.Writer
	seq    uint64
	prev   string
	events []EvidenceEvent
}

// NewJournal creates a signed evidence journal. If key is nil, an ephemeral
// key is generated; production deployments should supply a key from KMS/HSM or
// a managed signing service.
func NewJournal(ctx ReviewContext, key ed25519.PrivateKey, out io.Writer) (*Journal, error) {
	if ctx.SchemaVersion == "" {
		ctx.SchemaVersion = SchemaVersion
	}
	if ctx.DetectorVersion == "" {
		ctx.DetectorVersion = "dev"
	}
	if key == nil {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("generate evidence key: %w", err)
		}
		key = priv
		_ = pub
	}
	return &Journal{ctx: ctx, key: key, out: out}, nil
}

// Record appends an incident to the hash chain and, when configured, writes one
// compact JSON line. Callers that cannot tolerate disk latency should use
// AsyncRecorder.
func (j *Journal) Record(inc *Incident) error {
	if inc == nil {
		return nil
	}
	j.mu.Lock()
	defer j.mu.Unlock()

	j.seq++
	event := EvidenceEvent{
		SchemaVersion: SchemaVersion,
		Sequence:      j.seq,
		RecordedAt:    time.Now().UTC(),
		Incident:      inc,
		PrevHash:      j.prev,
	}
	event.Hash = hashEvent(event)
	j.events = append(j.events, event)
	j.prev = event.Hash

	if j.out != nil {
		line, err := json.Marshal(event)
		if err != nil {
			return fmt.Errorf("marshal evidence event: %w", err)
		}
		line = append(line, '\n')
		if _, err := j.out.Write(line); err != nil {
			return fmt.Errorf("write evidence event: %w", err)
		}
	}
	return nil
}

// Finalize returns a signed review bundle containing all recorded events.
func (j *Journal) Finalize(signedAt time.Time) (*ReviewBundle, error) {
	j.mu.Lock()
	defer j.mu.Unlock()

	if signedAt.IsZero() {
		signedAt = time.Now().UTC()
	}
	pub, ok := j.key.Public().(ed25519.PublicKey)
	if !ok || len(pub) != ed25519.PublicKeySize {
		return nil, errors.New("invalid ed25519 public key")
	}
	fp := sha256.Sum256(pub)
	bundle := &ReviewBundle{
		SchemaVersion:     SchemaVersion,
		Context:           j.ctx,
		Events:            append([]EvidenceEvent(nil), j.events...),
		EventCount:        len(j.events),
		RootHash:          j.prev,
		PublicKey:         pub,
		SignerFingerprint: hex.EncodeToString(fp[:]),
		SignedAt:          signedAt.UTC(),
	}
	payload, err := signingPayload(bundle)
	if err != nil {
		return nil, err
	}
	bundle.Signature = ed25519.Sign(j.key, payload)
	return bundle, nil
}

// Verify checks the hash chain, root hash, event count and Ed25519 signature.
// It does not decide whether the embedded signer is trusted; compare
// SignerFingerprint against an out-of-band pinned value.
func (b *ReviewBundle) Verify() error {
	if b == nil {
		return errors.New("nil bundle")
	}
	if b.SchemaVersion != SchemaVersion {
		return fmt.Errorf("unsupported schema %q", b.SchemaVersion)
	}
	if b.EventCount != len(b.Events) {
		return fmt.Errorf("event_count=%d but contains %d events", b.EventCount, len(b.Events))
	}
	prev := ""
	for i, event := range b.Events {
		if event.Sequence != uint64(i+1) {
			return fmt.Errorf("event %d has sequence %d", i, event.Sequence)
		}
		if event.PrevHash != prev {
			return fmt.Errorf("event %d previous hash mismatch", event.Sequence)
		}
		want := hashEvent(event)
		if event.Hash != want {
			return fmt.Errorf("event %d hash mismatch", event.Sequence)
		}
		prev = event.Hash
	}
	if prev != b.RootHash {
		return errors.New("root hash does not match hash chain")
	}
	if len(b.PublicKey) != ed25519.PublicKeySize {
		return errors.New("invalid public key length")
	}
	fp := sha256.Sum256(b.PublicKey)
	if got := hex.EncodeToString(fp[:]); got != b.SignerFingerprint {
		return errors.New("signer fingerprint mismatch")
	}
	payload, err := signingPayload(b)
	if err != nil {
		return err
	}
	if !ed25519.Verify(b.PublicKey, payload, b.Signature) {
		return errors.New("ed25519 signature verification failed")
	}
	return nil
}

// WriteJSON writes an indented bundle for referee tooling.
func (b *ReviewBundle) WriteJSON(w io.Writer) error {
	data, err := json.MarshalIndent(b, "", "  ")
	if err != nil {
		return err
	}
	data = append(data, '\n')
	_, err = w.Write(data)
	return err
}

func hashEvent(event EvidenceEvent) string {
	event.Hash = ""
	data, err := json.Marshal(event)
	if err != nil {
		// All incident fields are JSON-safe; a failure here is a programming
		// error rather than a recoverable runtime condition.
		panic(fmt.Errorf("hash evidence event: %w", err))
	}
	sum := sha256.Sum256(append([]byte(event.PrevHash+"\n"), data...))
	return hex.EncodeToString(sum[:])
}

func signingPayload(b *ReviewBundle) ([]byte, error) {
	toSign := struct {
		SchemaVersion string        `json:"schema_version"`
		Context       ReviewContext `json:"context"`
		EventCount    int           `json:"event_count"`
		RootHash      string        `json:"root_hash"`
		PublicKey     []byte        `json:"public_key"`
		Fingerprint   string        `json:"signer_fingerprint"`
		SignedAt      time.Time     `json:"signed_at"`
	}{
		SchemaVersion: b.SchemaVersion,
		Context:       b.Context,
		EventCount:    b.EventCount,
		RootHash:      b.RootHash,
		PublicKey:     []byte(b.PublicKey),
		Fingerprint:   b.SignerFingerprint,
		SignedAt:      b.SignedAt,
	}
	data, err := json.Marshal(toSign)
	if err != nil {
		return nil, fmt.Errorf("marshal signing payload: %w", err)
	}
	return data, nil
}
