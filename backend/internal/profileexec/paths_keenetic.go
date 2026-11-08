//go:build keenetic

package profileexec

const (
	Python      = "/opt/bin/python3"
	Compiler    = "/opt/lib/hestia/profile.py"
	Backend     = "/opt/lib/hestia/sing-box"
	CommandPath = "/opt/sbin:/opt/bin:/usr/sbin:/usr/bin:/sbin:/bin"
)

// backendCheckCommand invokes the Entware binary through its bundled dynamic loader and library path.
func backendCheckCommand(path string) (string, []string) {
	return "/opt/lib/ld-linux-aarch64.so.1", []string{"--library-path", "/opt/lib:/opt/lib/hestia", Backend, "check", "-c", path}
}
