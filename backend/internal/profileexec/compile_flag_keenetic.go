//go:build keenetic

package profileexec

// appendPlatformCompileFlag enables the narrowly scoped Keenetic underlay migration check.
func appendPlatformCompileFlag(args []string) []string { return append(args, "--keenetic") }
