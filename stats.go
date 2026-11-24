package lagguard

import "sort"

// floatRing is a fixed-capacity sample buffer. It never allocates on Add after
// construction.
type floatRing struct {
	values []float64
	head   int
	full   bool
}

func newFloatRing(capacity int) *floatRing {
	if capacity < 3 {
		capacity = 3
	}
	return &floatRing{values: make([]float64, capacity)}
}

func (r *floatRing) add(v float64) {
	if r == nil || len(r.values) == 0 {
		return
	}
	r.values[r.head] = v
	r.head = (r.head + 1) % len(r.values)
	if r.head == 0 {
		r.full = true
	}
}

func (r *floatRing) len() int {
	if r == nil {
		return 0
	}
	if r.full {
		return len(r.values)
	}
	return r.head
}

// median copies the occupied samples; call it only while scoring an incident,
// not on every fast-path packet.
func (r *floatRing) median() (float64, bool) {
	n := r.len()
	if r == nil || n == 0 {
		return 0, false
	}
	tmp := make([]float64, n)
	if r.full {
		copy(tmp, r.values)
	} else {
		copy(tmp, r.values[:n])
	}
	sort.Float64s(tmp)
	if n%2 == 1 {
		return tmp[n/2], true
	}
	return (tmp[n/2-1] + tmp[n/2]) / 2, true
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func clamp(v, lo, hi float64) float64 {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
