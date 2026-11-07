// Package keeneticphysical adapts authenticated Keenetic RCI observations to Hestia network contracts.
package keeneticphysical

import (
	"context"
	"path/filepath"
	"time"

	"github.com/Artik-Man/Hestia/internal/network"
	"github.com/Artik-Man/Hestia/internal/network/linuxphysical"
	"github.com/Artik-Man/Hestia/internal/panelmodel"
	"github.com/Artik-Man/Hestia/internal/storage"
	"github.com/Artik-Man/Hestia/pkg/keeneticrci"
)

const (
	requestTimeout = 1500 * time.Millisecond
)

// Manager exposes read-only native Ethernet inventory and rejects unsupported Wi-Fi mutations.
type Manager struct {
	connector *keeneticrci.EthernetConnector
	initErr   error
}

// NewManager creates the Keenetic physical inventory adapter over the shared RCI client.
func NewManager(client *keeneticrci.Client) (*Manager, error) {
	connector, err := keeneticrci.NewEthernetConnector(client)
	if err != nil {
		return nil, err
	}
	return &Manager{connector: connector}, nil
}

// InstalledManager selects the local RCI endpoint and token under the current Keenetic storage layout.
func InstalledManager() *Manager {
	client, err := installedClient()
	if err != nil {
		return &Manager{initErr: err}
	}
	manager, err := NewManager(client)
	if err != nil {
		return &Manager{initErr: err}
	}
	return manager
}

// Inventory reads typed native Ethernet ports without mapping their IDs to kernel interface names.
func (m *Manager) Inventory(ctx context.Context) (panelmodel.PhysicalInventory, error) {
	result := panelmodel.PhysicalInventory{
		Interfaces:   []panelmodel.PhysicalInterface{},
		WifiProfiles: []panelmodel.WifiConnection{},
	}
	devices, err := (linuxphysical.Manager{}).KernelInventory()
	if err != nil {
		return result, err
	}
	result.Interfaces = devices
	if m.initErr != nil {
		return result, m.initErr
	}
	inventory, err := m.connector.Read(ctx)
	if err != nil {
		return result, err
	}
	result.NativeEthernetPorts = make([]panelmodel.NativeEthernetPort, 0, len(inventory.Ports))
	for _, port := range inventory.Ports {
		item := panelmodel.NativeEthernetPort{ID: port.ID, Link: string(port.Link), SpeedMbps: port.SpeedMbps, ExitIDs: []string{}}
		if port.Duplex != nil {
			duplex := string(*port.Duplex)
			item.Duplex = &duplex
		}
		result.NativeEthernetPorts = append(result.NativeEthernetPorts, item)
	}
	return result, nil
}

// SaveWiFi refuses to create or modify a WISP profile before its Keenetic RCI contract is verified.
func (m *Manager) SaveWiFi(context.Context, string, panelmodel.WifiConnectionSettings) error {
	return network.ErrUnsupported
}

// DeleteWiFi refuses to delete a WISP profile before its Keenetic RCI contract is verified.
func (m *Manager) DeleteWiFi(context.Context, string) error { return network.ErrUnsupported }

// installedClient creates the one authenticated transport configuration shared by installed RCI adapters.
func installedClient() (*keeneticrci.Client, error) {
	return keeneticrci.NewClient(keeneticrci.Config{
		BaseURL: "http://127.0.0.1:79",
		TokenSource: keeneticrci.FileTokenSource{
			Path: filepath.Join(storage.Installed().Config, "keenetic-rci-token"),
		},
		Timeout: requestTimeout,
	})
}

// Carrier observes a selected Linux interface through kernel sysfs, never by treating an RCI port ID as a device name.
type Carrier struct{ sysfs string }

// InstalledCarrier creates the kernel carrier reader for the default Linux sysfs location.
func InstalledCarrier() *Carrier { return &Carrier{} }

// Online reports only a link explicitly confirmed by the kernel for the given Linux device.
// Online returns true only when sysfs explicitly confirms an active link for the kernel device name.
func (c *Carrier) Online(device string) bool {
	return c.State(device) == panelmodel.CarrierUp
}

// State preserves an unavailable sysfs carrier observation as unknown.
func (c *Carrier) State(device string) panelmodel.CarrierState {
	sysfs := c.sysfs
	if sysfs == "" {
		sysfs = "/sys/class/net"
	}
	return linuxphysical.CarrierStateAt(sysfs, device)
}

var _ network.Carrier = (*Carrier)(nil)
var _ network.Physical = (*Manager)(nil)
