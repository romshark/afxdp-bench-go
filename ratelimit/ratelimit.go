// Package ratelimit provides a simple packets-per-second rate limiter.
package ratelimit

import "time"

// Throttle limits to pps packets per second on average.
// Not safe for concurrent use.
type Throttle struct {
	nsPerPacket int64
	packetsSent uint64
	startTime   time.Time
	checkEvery  uint64
}

// New creates a limiter for pps packets per second.
// If pps == 0, throttling is disabled.
func New(pps uint64) *Throttle {
	if pps == 0 {
		return nil
	}
	return &Throttle{
		nsPerPacket: int64(time.Second) / int64(pps),
		startTime:   time.Now(),

		// Check time every ~10ms of packets to balance accuracy vs overhead
		// At least every 32 packets. At most every 1024 packets.
		checkEvery: min(max(pps/100, 32), 1024),
	}
}

// ThrottleN blocks until n packets are allowed.
// It does not "catch up" by allowing faster sends after being delayed.
func (l *Throttle) ThrottleN(n uint64) {
	if l == nil || n == 0 {
		return
	}

	l.packetsSent += n
	if l.packetsSent%l.checkEvery != 0 {
		return // Fast path: only check time periodically.
	}

	// Slow path: check if we need to sleep
	expectedTime := l.startTime.Add(time.Duration(int64(l.packetsSent) * l.nsPerPacket))

	if now := time.Now(); now.Before(expectedTime) {
		time.Sleep(expectedTime.Sub(now))
	}
	// If behind schedule, naturally catch up by not sleeping
}
