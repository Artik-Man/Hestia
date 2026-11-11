package binding

import (
	"testing"
	"time"
)

// TestCommandTimeoutKeepsIngressMigrationBounded verifies only ingress enablement receives the longer overall deadline.
func TestCommandTimeoutKeepsIngressMigrationBounded(t *testing.T) {
	cases := []struct {
		mode string
		want time.Duration
	}{
		{mode: "-enable-keenetic-ingress", want: AWGActivationLimit},
		{mode: "-disable-keenetic-ingress", want: 2 * time.Minute},
		{mode: "-apply-binding", want: 2 * time.Minute},
		{mode: "-recover-bindings", want: AWGActivationLimit},
		{mode: "-watch-pending-binding", want: 3*AWGActivationLimit + time.Minute},
	}
	for _, test := range cases {
		t.Run(test.mode, func(t *testing.T) {
			if got := CommandTimeout(test.mode); got != test.want {
				t.Fatalf("CommandTimeout(%q) = %s, want %s", test.mode, got, test.want)
			}
			if got := CommandTimeout(test.mode); got <= 0 {
				t.Fatalf("CommandTimeout(%q) = %s, must remain finite and positive", test.mode, got)
			}
		})
	}
}
