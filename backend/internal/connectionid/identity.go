// Package connectionid defines shared connector identity validation.
package connectionid

import "regexp"

// ConnectionIDPattern matches a routing ID inside a larger expression: a UUID or a historical connector tag.
const ConnectionIDPattern = "(?:[a-z][a-z0-9-]{0,62}|[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})"

var connectionID = regexp.MustCompile("^" + ConnectionIDPattern + "$")

// ValidConnectionID accepts a canonical lowercase UUID or a legacy tag safe for paths, systemd instances and routing.
func ValidConnectionID(id string) bool {
	return connectionID.MatchString(id)
}
