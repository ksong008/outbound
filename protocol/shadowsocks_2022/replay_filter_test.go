package shadowsocks_2022

import "testing"

func TestSlidingWindowFilterRejectsDuplicates(t *testing.T) {
	filter := NewSlidingWindowFilter(4)
	if !filter.CheckAndUpdate(1) {
		t.Fatal("expected first packet to pass")
	}
	if filter.CheckAndUpdate(1) {
		t.Fatal("expected duplicate packet to be rejected")
	}
}

func TestSlidingWindowFilterRejectsTooOldPacket(t *testing.T) {
	filter := NewSlidingWindowFilter(4)
	for _, packetID := range []uint64{10, 11, 12, 13, 14} {
		if !filter.CheckAndUpdate(packetID) {
			t.Fatalf("expected packet %d to pass", packetID)
		}
	}
	if filter.CheckAndUpdate(10) {
		t.Fatal("expected packet outside the sliding window to be rejected")
	}
}
