package testutil

import (
	"os"
	"testing"
)

const LiveIntegrationEnv = "OUTBOUND_LIVE_TEST"

func RequireLiveIntegration(t testing.TB, detail string) {
	t.Helper()
	if os.Getenv(LiveIntegrationEnv) == "1" {
		return
	}
	if detail == "" {
		detail = "requires live remote services"
	}
	t.Skipf("skipping live integration test; set %s=1 to enable (%s)", LiveIntegrationEnv, detail)
}
