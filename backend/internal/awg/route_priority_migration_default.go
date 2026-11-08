//go:build !keenetic

package awg

import "context"

// migrateLegacyRouteManifest is a no-op on Linux, whose reserved priorities remain stable.
func migrateLegacyRouteManifest(context.Context, string, routeManifest, int) error { return nil }
