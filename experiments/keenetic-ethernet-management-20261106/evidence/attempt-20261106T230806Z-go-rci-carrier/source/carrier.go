// Package keeneticphysical adapts verified Keenetic RCI link state to Hestia network contracts.
package keeneticphysical

import (
	"context"
	"path/filepath"
	"sync"
	"time"

	"github.com/Artik-Man/Hestia/internal/network"
	"github.com/Artik-Man/Hestia/internal/storage"
	"github.com/Artik-Man/Hestia/pkg/keeneticrci"
)

const (
	requestTimeout = 1500 * time.Millisecond
	cacheLifetime  = 500 * time.Millisecond
)

// Carrier reports RCI link state, treating stale, missing, and unreadable observations as offline.
type Carrier struct {
	connector *keeneticrci.EthernetConnector
	mu        sync.Mutex
	links     map[string]bool
	expires   time.Time
}

// NewCarrier creates a read-only link observer over the authenticated RCI client.
func NewCarrier(client *keeneticrci.Client) (*Carrier, error) {
	connector, err := keeneticrci.NewEthernetConnector(client)
	if err != nil {
		return nil, err
	}
	return &Carrier{connector: connector, links: make(map[string]bool)}, nil
}

// InstalledCarrier creates the RCI observer for the token installed under the selected platform layout.
func InstalledCarrier() (*Carrier, error) {
	client, err := keeneticrci.NewClient(keeneticrci.Config{
		BaseURL: "http://127.0.0.1:79",
		TokenSource: keeneticrci.FileTokenSource{
			Path: filepath.Join(storage.Installed().Config, "keenetic-rci-token"),
		},
		Timeout: requestTimeout,
	})
	if err != nil {
		return nil, err
	}
	return NewCarrier(client)
}

// Online returns true only for a fresh RCI observation that explicitly reports the named physical port up.
func (c *Carrier) Online(id string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	if !now.Before(c.expires) {
		c.refresh(now)
	}
	return c.links[id]
}

// refresh replaces the cached snapshot; every request failure clears prior state and fails closed.
func (c *Carrier) refresh(now time.Time) {
	c.links = make(map[string]bool)
	ctx, cancel := context.WithTimeout(context.Background(), requestTimeout)
	defer cancel()
	inventory, err := c.connector.Read(ctx)
	c.expires = now.Add(cacheLifetime)
	if err != nil {
		return
	}
	for _, port := range inventory.Ports {
		c.links[port.ID] = port.Link == keeneticrci.LinkUp
	}
}

var _ network.Carrier = (*Carrier)(nil)
