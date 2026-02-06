package scanner

import (
	"sync"
	"time"
)

const (
	maxHistory = 10
	newTimeout = 30 * time.Second
)

// sparkBlocks maps signal intensity (0–7) to Unicode block characters.
var sparkBlocks = []rune{'▁', '▂', '▃', '▄', '▅', '▆', '▇', '█'}

// NetworkState tracks per-BSSID state across scan cycles.
type NetworkState struct {
	BSSID         string
	FirstSeen     time.Time
	LastSeen      time.Time
	SignalHistory []int
	MinSignal     int
	MaxSignal     int
}

// IsNew returns true if this network was first seen within the last 30 seconds.
func (ns *NetworkState) IsNew() bool {
	return time.Since(ns.FirstSeen) < newTimeout
}

// Sparkline returns a Unicode sparkline string for the last 10 signal readings.
func (ns *NetworkState) Sparkline() string {
	if len(ns.SignalHistory) == 0 {
		return ""
	}
	runes := make([]rune, len(ns.SignalHistory))
	for i, sig := range ns.SignalHistory {
		// Map dBm range (-100 to -20) into 0–7
		idx := (sig + 100) * 7 / 80
		if idx < 0 {
			idx = 0
		}
		if idx > 7 {
			idx = 7
		}
		runes[i] = sparkBlocks[idx]
	}
	return string(runes)
}

// Session tracks network state across multiple scan cycles.
type Session struct {
	mu     sync.Mutex
	states map[string]*NetworkState
}

// NewSession creates an empty session tracker.
func NewSession() *Session {
	return &Session{
		states: make(map[string]*NetworkState),
	}
}

// Update processes a new batch of scan results, updating state for each network.
// Returns a list of BSSIDs that are newly discovered (first seen this call).
func (s *Session) Update(networks []Network) []string {
	s.mu.Lock()
	defer s.mu.Unlock()

	var newBSSIDs []string
	now := time.Now()

	for _, net := range networks {
		state, exists := s.states[net.BSSID]
		if !exists {
			state = &NetworkState{
				BSSID:     net.BSSID,
				FirstSeen: now,
				MinSignal: net.Signal,
				MaxSignal: net.Signal,
			}
			s.states[net.BSSID] = state
			newBSSIDs = append(newBSSIDs, net.BSSID)
		}

		state.LastSeen = now

		// Track min/max
		if net.Signal < state.MinSignal {
			state.MinSignal = net.Signal
		}
		if net.Signal > state.MaxSignal {
			state.MaxSignal = net.Signal
		}

		// Append to history, keeping last maxHistory entries
		state.SignalHistory = append(state.SignalHistory, net.Signal)
		if len(state.SignalHistory) > maxHistory {
			state.SignalHistory = state.SignalHistory[len(state.SignalHistory)-maxHistory:]
		}
	}

	return newBSSIDs
}

// Get returns the state for a given BSSID, or nil if not tracked.
func (s *Session) Get(bssid string) *NetworkState {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.states[bssid]
}

// Count returns the total number of tracked networks.
func (s *Session) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.states)
}
