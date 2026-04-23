package shadowsocks_2022

import "sync"

type SlidingWindowFilter struct {
	windowSize int
	latest     uint64
	seen       map[uint64]struct{}
	mu         sync.Mutex
	init       bool
}

func NewSlidingWindowFilter(windowSize int) *SlidingWindowFilter {
	if windowSize <= 0 {
		windowSize = 4096
	}
	return &SlidingWindowFilter{
		windowSize: windowSize,
		seen:       make(map[uint64]struct{}, windowSize),
	}
}

func (f *SlidingWindowFilter) CheckAndUpdate(packetID uint64) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	if !f.init {
		f.latest = packetID
		f.seen[packetID] = struct{}{}
		f.init = true
		return true
	}

	if packetID+uint64(f.windowSize) <= f.latest {
		return false
	}
	if _, ok := f.seen[packetID]; ok {
		return false
	}

	if packetID > f.latest {
		f.latest = packetID
		cutoff := f.latest - uint64(f.windowSize)
		for seenID := range f.seen {
			if seenID <= cutoff {
				delete(f.seen, seenID)
			}
		}
	}

	f.seen[packetID] = struct{}{}
	return true
}
