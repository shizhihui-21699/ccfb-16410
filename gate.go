package lagguard

import (
	"errors"
	"sync"
	"sync/atomic"
)

// ErrEvidenceQueueFull indicates that the asynchronous evidence queue is full.
// The media path is never blocked: increment an operational alert and, for
// competitive sessions, prefer synchronous out-of-band capture by a sidecar
// rather than stalling packets.
var ErrEvidenceQueueFull = errors.New("evidence queue full")

// Gate combines the per-stream detector, evidence sink and a non-blocking
// decision callback. A Gate is owned by one stream goroutine.
type Gate struct {
	Detector   *Detector
	Recorder   Recorder
	OnDecision func(Decision, *Incident)
	OnError    func(error)
}

// Observe inspects metadata and fans resulting incidents to evidence and the
// control plane. All configured callbacks should be non-blocking.
func (g *Gate) Observe(p Packet) Result {
	res := g.Detector.Observe(p)
	if res.Incident == nil {
		return res
	}

	incidents := res.Incidents
	if len(incidents) == 0 {
		incidents = []*Incident{res.Incident}
	}
	for _, inc := range incidents {
		if g.Recorder != nil {
			if err := g.Recorder.Record(inc); err != nil && g.OnError != nil {
				g.OnError(err)
			}
		}
	}
	if g.OnDecision != nil {
		g.OnDecision(res.Decision, res.Incident)
	}
	return res
}

// Flush completes and records the active burst at stream shutdown.
func (g *Gate) Flush() *Incident {
	inc := g.Detector.Flush()
	if inc == nil {
		return nil
	}
	if g.Recorder != nil {
		if err := g.Recorder.Record(inc); err != nil && g.OnError != nil {
			g.OnError(err)
		}
	}
	if g.OnDecision != nil {
		g.OnDecision(inc.Decision, inc)
	}
	return inc
}

// AsyncRecorder moves journal writes off the packet goroutine.
type AsyncRecorder struct {
	journal  *Journal
	ch       chan *Incident
	wg       sync.WaitGroup
	closed   atomic.Bool
	dropped  atomic.Uint64
	writeErr error
}

// NewAsyncRecorder starts a background journal writer.
func NewAsyncRecorder(journal *Journal, queueSize int) *AsyncRecorder {
	if queueSize < 64 {
		queueSize = 64
	}
	a := &AsyncRecorder{
		journal: journal,
		ch:      make(chan *Incident, queueSize),
	}
	a.wg.Add(1)
	go func() {
		defer a.wg.Done()
		for inc := range a.ch {
			if err := journal.Record(inc); err != nil && a.writeErr == nil {
				a.writeErr = err
			}
		}
	}()
	return a
}

// Record enqueues an incident without disk IO. It returns
// ErrEvidenceQueueFull instead of blocking.
func (a *AsyncRecorder) Record(inc *Incident) error {
	if a.closed.Load() {
		return errors.New("async recorder closed")
	}
	select {
	case a.ch <- inc:
		return nil
	default:
		a.dropped.Add(1)
		return ErrEvidenceQueueFull
	}
}

// Dropped reports evidence records shed because the queue was full.
func (a *AsyncRecorder) Dropped() uint64 { return a.dropped.Load() }

// Close flushes queued records, stops the writer and returns the first
// background write error if one occurred.
func (a *AsyncRecorder) Close() error {
	if a.closed.Swap(true) {
		return nil
	}
	close(a.ch)
	a.wg.Wait()
	return a.writeErr
}

// Journal returns the underlying hash-chained journal.
func (a *AsyncRecorder) Journal() *Journal { return a.journal }
