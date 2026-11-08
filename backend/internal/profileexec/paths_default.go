//go:build !keenetic

package profileexec

const (
	Python      = "/usr/bin/python3"
	Compiler    = "/usr/local/lib/hestia/profile.py"
	Backend     = "/usr/local/lib/hestia/sing-box"
	CommandPath = "/usr/sbin:/usr/bin:/sbin:/bin"
)

// backendCheckCommand invokes the platform binary directly for the standard Linux installation.
func backendCheckCommand(path string) (string, []string) {
	return Backend, []string{"check", "-c", path}
}
