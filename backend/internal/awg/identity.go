package awg

import "github.com/Artik-Man/Hestia/internal/connectionid"

// ConnectionIDPattern matches a canonical UUID or historical connector tag.
const ConnectionIDPattern = connectionid.ConnectionIDPattern

// ValidConnectionID accepts identities safe for paths, service instances and routing.
func ValidConnectionID(id string) bool { return connectionid.ValidConnectionID(id) }
