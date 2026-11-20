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

	// Wrong, used or expired codes: a client with codeFailLimit failures
	// within codeFailWindow is blocked for codeBlock.
	codeFailLimit  = 5
	codeFailWindow = 15 * time.Minute
	codeBlock      = 15 * time.Minute

	// Wrong codes from all clients together: above globalFailLimit in a
	// globalFailWindow, code enrollment is refused for everyone until the
	// window ends.
	globalFailLimit  = 30
	globalFailWindow = 15 * time.Minute

	// Entries idle this long are dropped; the maps never hold more than
	// maxClients entries (new clients are refused while full).
	idleExpiry = 30 * time.Minute
	maxClients = 65536
)

type clientState struct {
	tokens       float64
	last         time.Time
	fails        int
	failStart    time.Time
	blockedUntil time.Time
}

type limiter struct {
	mu          sync.Mutex
	clients     map[string]*clientState
	lastSweep   time.Time
	globalFails int
	globalStart time.Time
}

func newLimiter() *limiter {
	return &limiter{clients: make(map[string]*clientState)}
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

func (l *limiter) state(key string, now time.Time) *clientState {
	if now.Sub(l.lastSweep) > time.Minute {
		for k, s := range l.clients {
			if now.Sub(s.last) > idleExpiry && now.After(s.blockedUntil) {
				delete(l.clients, k)
			}
		}
		l.lastSweep = now
	}
	s := l.clients[key]
	if s == nil {
		if len(l.clients) >= maxClients {
			return nil
		}
		s = &clientState{tokens: postBurst, last: now}
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
	if s == nil {
		return false, time.Minute
	}
	s.tokens = min(postBurst, s.tokens+now.Sub(s.last).Seconds()*postRate)
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
	if l.globalFails >= globalFailLimit && now.Sub(l.globalStart) < globalFailWindow {
		return false, globalFailWindow - now.Sub(l.globalStart)
	}
	s := l.state(key, now)
	if s == nil {
		return false, time.Minute
	}
	if now.Before(s.blockedUntil) {
		return false, s.blockedUntil.Sub(now)
	}
	return true, 0
}

// codeFailed records a wrong, used or expired code.
func (l *limiter) codeFailed(key string, now time.Time) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if now.Sub(l.globalStart) >= globalFailWindow {
		l.globalStart, l.globalFails = now, 0
	}
	l.globalFails++
	s := l.state(key, now)
	if s == nil {
		return
	}
	if now.Sub(s.failStart) >= codeFailWindow {
		s.failStart, s.fails = now, 0
	}
	s.fails++
	if s.fails >= codeFailLimit {
		s.blockedUntil = now.Add(codeBlock)
		s.fails = 0
	}
}
