package binding

import "github.com/Artik-Man/Hestia/internal/profileexec"

// profileCompiler returns the installed platform compiler or the isolated command-backed test adapter.
func (e Engine) profileCompiler() profileexec.CompilerAPI {
	if e.compiler != nil {
		return e.compiler
	}
	return profileexec.Installed{Run: e.run}
}
