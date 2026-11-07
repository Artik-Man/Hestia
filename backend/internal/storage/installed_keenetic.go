//go:build keenetic

package storage

// Installed selects the Entware-oriented layout for builds with the Keenetic tag.
func Installed() Layout { return Keenetic() }
