//go:build !keenetic

package profileexec

const (
	Python      = "/usr/bin/python3"
	Compiler    = "/usr/local/lib/hestia/profile.py"
	Backend     = "/usr/local/lib/hestia/sing-box"
	CommandPath = "/usr/sbin:/usr/bin:/sbin:/bin"
)
