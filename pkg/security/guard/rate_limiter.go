package guard

import (
	"sync"
	"time"
)

// clientBucket tracks token bucket metrics for an individual remote client.
type clientBucket struct {
	tokens         float64
	lastUpdate     time.Time
	violations     int
	bannedUntil    time.Time
}

// RateLimiter provides thread-safe IP rate limiting and anti-flood protection.
type RateLimiter struct {
	mu                   sync.Mutex
	enabled              bool
	rps                  float64       // Requests per second
	burst                float64       // Burst capacity
	banThreshold         int           // Violations before ban
	banDuration          time.Duration // Duration of temporary ban
	buckets              map[string]*clientBucket
	whitelist            *ProcessWhitelist
	cleanupInterval      time.Duration
	stopCleanup          chan struct{}
}

// NewRateLimiter creates a new RateLimiter.
func NewRateLimiter(enabled bool, rps float64, burst int, banThreshold int, banDurationSec int, whitelist *ProcessWhitelist) *RateLimiter {
	if rps <= 0 {
		rps = 50.0
	}
	if burst <= 0 {
		burst = 100
	}
	if banThreshold <= 0 {
		banThreshold = 20
	}
	if banDurationSec <= 0 {
		banDurationSec = 300
	}

	rl := &RateLimiter{
		enabled:         enabled,
		rps:             rps,
		burst:           float64(burst),
		banThreshold:    banThreshold,
		banDuration:     time.Duration(banDurationSec) * time.Second,
		buckets:         make(map[string]*clientBucket),
		whitelist:       whitelist,
		cleanupInterval: 1 * time.Minute,
		stopCleanup:     make(chan struct{}),
	}

	go rl.startCleanupLoop()
	return rl
}

// Allow evaluates if a request from the given client key (usually IP) is permitted.
func (rl *RateLimiter) Allow(clientKey string) bool {
	if !rl.enabled {
		return true
	}

	if rl.whitelist != nil && rl.whitelist.IsIPProtected(clientKey) {
		return true
	}

	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	bucket, exists := rl.buckets[clientKey]
	if !exists {
		bucket = &clientBucket{
			tokens:     rl.burst - 1.0,
			lastUpdate: now,
		}
		rl.buckets[clientKey] = bucket
		return true
	}

	// 1. Check if currently banned
	if now.Before(bucket.bannedUntil) {
		return false
	}

	// 2. Refill tokens according to elapsed time
	elapsed := now.Sub(bucket.lastUpdate).Seconds()
	bucket.lastUpdate = now
	bucket.tokens += elapsed * rl.rps
	if bucket.tokens > rl.burst {
		bucket.tokens = rl.burst
	}

	// 3. Consume token or flag violation
	if bucket.tokens >= 1.0 {
		bucket.tokens -= 1.0
		return true
	}

	// Rate limit exceeded: record violation
	bucket.violations++
	if bucket.violations >= rl.banThreshold {
		bucket.bannedUntil = now.Add(rl.banDuration)
		bucket.violations = 0 // reset counter for next cycle
	}

	return false
}

// IsBanned returns true if the client is currently undergoing temporary isolation.
func (rl *RateLimiter) IsBanned(clientKey string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	bucket, exists := rl.buckets[clientKey]
	if !exists {
		return false
	}
	return time.Now().Before(bucket.bannedUntil)
}

// Unban explicitly removes an IP from the ban list.
func (rl *RateLimiter) Unban(clientKey string) {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	if bucket, exists := rl.buckets[clientKey]; exists {
		bucket.bannedUntil = time.Time{}
		bucket.violations = 0
		bucket.tokens = rl.burst
	}
}

// Stop cleanly terminates the background cleanup goroutine.
func (rl *RateLimiter) Stop() {
	select {
	case <-rl.stopCleanup:
	default:
		close(rl.stopCleanup)
	}
}

func (rl *RateLimiter) startCleanupLoop() {
	ticker := time.NewTicker(rl.cleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-rl.stopCleanup:
			return
		case <-ticker.C:
			rl.mu.Lock()
			now := time.Now()
			for key, bucket := range rl.buckets {
				// Expire inactive and unbanned buckets after 10 minutes
				if now.After(bucket.bannedUntil) && now.Sub(bucket.lastUpdate) > 10*time.Minute {
					delete(rl.buckets, key)
				}
			}
			rl.mu.Unlock()
		}
	}
}
