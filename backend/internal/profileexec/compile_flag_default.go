//go:build !keenetic

package profileexec

// appendPlatformCompileFlag leaves the Linux compiler invocation unchanged.
func appendPlatformCompileFlag(args []string) []string { return args }
