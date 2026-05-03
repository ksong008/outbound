package direct

import "testing"

func TestGetDirectDialerInitializesMissingGlobals(t *testing.T) {
	prevSymmetric := SymmetricDirect
	prevFullcone := FullconeDirect
	SymmetricDirect = nil
	FullconeDirect = nil
	t.Cleanup(func() {
		SymmetricDirect = prevSymmetric
		FullconeDirect = prevFullcone
	})

	if got := GetDirectDialer(false); got == nil {
		t.Fatal("expected symmetric direct dialer to be initialized")
	}
	if got := GetDirectDialer(true); got == nil {
		t.Fatal("expected fullcone direct dialer to be initialized")
	}
}
