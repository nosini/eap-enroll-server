// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

package enroll

import (
	"net"
	"net/netip"
	"sync"
	"time"
)

// Rate limits. Enrollment is rare (a phone enrolls once and renews every
// few weeks), so these are tight.
const (
	// Every POST: a token bucket per client.
	postRate  = 10.0 / 60 // tokens per second
	postBurst = 5

	// Authenticated requests: a token bucket per device, with the same
	// rate but a larger burst, since setting up a phone takes several
	// requests in a row (profile, Wi-Fi certificate, confirmation,
	// retries). What a device can be issued is capped separately.
	deviceBurst = 10

	// Wrong, used or expired codes: a client with codeFailLimit failures
	// within codeFailWindow is blocked for codeBlock.
	codeFailLimit  = 5
	codeFailWindow = 15 * time.Minute
	codeBlock      = 15 * time.Minute

	// Wrong codes from all clients together: globalFailLimit within
	// globalFailWindow only logs one warning; it never refuses anything,
	// because a usable code is an unguessable secret.
	globalFailLimit  = 30
	globalFailWindow = 15 * time.Minute

	// Entries idle this long are dropped. The map holds at most
	// maxClients entries; when it is full, entries are evicted, never
	// refused.
	idleExpiry = 30 * time.Minute
	maxClients = 65536

	// evictScan bounds how many entries a full map is scanned for an
	// unblocked one to evict.
	evictScan = 256
)

type clientState struct {
	tokens       float64
	last         time.Time
	fails        int
	failStart    time.Time
	blockedUntil time.Time
}

type limiter struct {
	mu           sync.Mutex
	clients      map[string]*clientState
	max          int     // maxClients, lower in tests
	burst        float64 // bucket size
	lastSweep    time.Time
	globalFails  int
	globalStart  time.Time
	globalWarned bool
}

func newLimiter(burst float64) *limiter {
	return &limiter{clients: make(map[string]*clientState), max: maxClients, burst: burst}
}

// clientKey groups IPv6 clients by /64, since one host usually has a
// whole /64.
func clientKey(remoteAddr string) string {
	host, _, err := net.SplitHostPort(remoteAddr)
	if err != nil {
		host = remoteAddr
	}
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return host
	}
	addr = addr.Unmap()
	if addr.Is6() {
		p, _ := addr.WithZone("").Prefix(64)
		return p.String()
	}
	return addr.String()
}

// sweep drops entries that have been idle and aren't blocked.
func (l *limiter) sweep(now time.Time) {
	for k, s := range l.clients {
		if now.Sub(s.last) > idleExpiry && now.After(s.blockedUntil) {
			delete(l.clients, k)
		}
	}
	l.lastSweep = now
}

// evict makes room for a new key in a full map. It prefers an entry that
// isn't blocked, scanning at most evictScan entries in map order; if all
// of those are blocked, it evicts the first one seen.
func (l *limiter) evict(now time.Time) {
	var first, unblocked string
	scanned := 0
	for k, s := range l.clients {
		if scanned == 0 {
			first = k
		}
		scanned++
		if !now.Before(s.blockedUntil) {
			unblocked = k
			break
		}
		if scanned >= evictScan {
			break
		}
	}
	if unblocked != "" {
		delete(l.clients, unblocked)
	} else if first != "" {
		delete(l.clients, first)
	}
}

// state returns the client's entry, creating it if needed. It never
// returns nil: in a full map, an entry is evicted to make room.
func (l *limiter) state(key string, now time.Time) *clientState {
	// Sweeping is a full scan, so at most once a minute: sweeping on every
	// new key of a full map would let new addresses buy CPU time under
	// the lock.
	if now.Sub(l.lastSweep) > time.Minute {
		l.sweep(now)
	}
	s := l.clients[key]
	if s == nil {
		if len(l.clients) >= l.max {
			l.evict(now)
		}
		s = &clientState{tokens: l.burst, last: now}
		l.clients[key] = s
	}
	return s
}

// allow takes a token for a POST; if none is left it returns how long to
// wait.
func (l *limiter) allow(key string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.state(key, now)
	s.tokens = min(l.burst, s.tokens+now.Sub(s.last).Seconds()*postRate)
	s.last = now
	if s.tokens < 1 {
		return false, time.Duration((1-s.tokens)/postRate*float64(time.Second)) + time.Second
	}
	s.tokens--
	return true, 0
}

// codeAllowed says whether a client may try a code now.
func (l *limiter) codeAllowed(key string, now time.Time) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	s := l.state(key, now)
	if now.Before(s.blockedUntil) {
		return false, s.blockedUntil.Sub(now)
	}
	return true, 0
}

// codeFailed records a wrong, used or expired code. It returns true when
// the global failure count has just reached globalFailLimit in this
// window, so the caller logs one warning; it never refuses anything.
func (l *limiter) codeFailed(key string, now time.Time) (warn bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.globalStart) >= globalFailWindow {
		l.globalStart, l.globalFails, l.globalWarned = now, 0, false
	}
	l.globalFails++
	if l.globalFails >= globalFailLimit && !l.globalWarned {
		l.globalWarned = true
		warn = true
	}
	s := l.state(key, now)
	if now.Sub(s.failStart) >= codeFailWindow {
		s.failStart, s.fails = now, 0
	}
	s.fails++
	if s.fails >= codeFailLimit {
		s.blockedUntil = now.Add(codeBlock)
		s.fails = 0
	}
	return warn
}
