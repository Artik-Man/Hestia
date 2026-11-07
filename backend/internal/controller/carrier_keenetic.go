//go:build keenetic

package controller

import (
	"github.com/Artik-Man/Hestia/internal/network/keeneticphysical"
	"github.com/Artik-Man/Hestia/internal/panelmodel"
)

// installedCarrier selects sysfs observations for Linux kernel device names; native RCI port IDs are not device names.
func installedCarrier() func(string) panelmodel.CarrierState {
	return keeneticphysical.InstalledCarrier().State
}
