//go:build !keenetic

package controller

import (
	"github.com/Artik-Man/Hestia/internal/network/linuxphysical"
	"github.com/Artik-Man/Hestia/internal/panelmodel"
)

// installedCarrier selects the existing Linux sysfs observation.
func installedCarrier() func(string) panelmodel.CarrierState { return linuxphysical.Manager{}.State }
