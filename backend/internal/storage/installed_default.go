//go:build !keenetic

package storage

// Installed selects the standalone Linux layout for builds without the Keenetic tag.
func Installed() Layout { return Linux() }
