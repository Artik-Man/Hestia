package binding

import "time"

const (
	defaultCommandTimeout = 2 * time.Minute
)

// CommandTimeout returns the bounded deadline for one fixed Hestia binding command mode.
func CommandTimeout(mode string) time.Duration {
	switch mode {
	case "-recover-bindings":
		return AWGActivationLimit
	case "-watch-pending-binding":
		// Allow the active writer to finish its deadline and rollback before taking the lock.
		return 3*AWGActivationLimit + time.Minute
	case "-enable-keenetic-ingress", "-enable-cpu-profiling", "-disable-cpu-profiling":
		// Leave room for the backend check plus staging and activation overhead.
		return AWGActivationLimit
	default:
		return defaultCommandTimeout
	}
}
