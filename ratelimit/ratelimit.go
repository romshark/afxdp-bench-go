// Package ratelimit provides a simple packets-per-second rate limiter.
package ratelimit

import "time"

// Limiter limits to pps packets per second on average.
// Not safe for concurrent use.
type Limiter struct {
	pps      uint64
	interval time.Duration
	next     time.Time
}

// New creates a limiter for pps packets per second.
// If pps == 0, throttling is disabled.
func New(pps uint64) *Limiter {
	if pps == 0 {
		return &Limiter{pps: 0}
	}
	interval := time.Second / time.Duration(pps)
	if interval <= 0 {
		interval = 1
	}
	return &Limiter{
		pps:      pps,
		interval: interval,
		next:     time.Now(),
	}
}

// ThrottleN blocks until n packets are allowed.
// It does not "catch up" by allowing faster sends after being delayed.
func (l *Limiter) ThrottleN(n uint64) {
	if l.pps == 0 || n == 0 {
		return
	}

	now := time.Now()
	base := now
	if now.Before(l.next) {
		time.Sleep(time.Until(l.next))
		base = l.next
	}

	// Next allowed time after reserving n packets worth of time.
	// (n is small here; if you ever pass huge n, guard overflow.)
	l.next = base.Add(time.Duration(n) * l.interval)
}
