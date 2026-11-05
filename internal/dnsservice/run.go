package dnsservice

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"time"

	"github.com/Artik-Man/Hestia/internal/dnspolicy"
	"github.com/Artik-Man/Hestia/internal/dnsresolver"
)

// serviceConfig specifies the router-facing socket, sole allowed client, and explicit direct-exit DNS IPs.
type serviceConfig struct {
	Listen netip.AddrPort    `json:"listen"`
	Router netip.Addr        `json:"router"`
	Direct map[string]string `json:"directResolvers"`
}

// Run starts the installed DNS worker on its configured private address until cancellation.
func Run(ctx context.Context, configPath string) error {
	file, err := os.Open(configPath)
	if err != nil {
		return err
	}
	defer file.Close()
	var cfg serviceConfig
	dec := json.NewDecoder(file)
	dec.DisallowUnknownFields()
	if err = dec.Decode(&cfg); err != nil {
		return err
	}
	if err = dec.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return errors.New("trailing DNS configuration")
	}
	if err = validateListener(cfg.Listen, cfg.Router); err != nil {
		return err
	}
	routes, err := loadRoutes("/run/hestia-dns/paths.json", cfg.Direct)
	if err != nil {
		return err
	}
	store := dnspolicy.Store{Path: "/var/lib/hestia-dns-policy/policy.json"}
	if _, err = store.Read(); err != nil {
		return err
	}
	resolver := dnsresolver.New(store, routes, "/var/lib/hestia-dns/cache.json")
	ctx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	var workers sync.WaitGroup
	err = serve(ctx, cfg.Listen, cfg.Router, resolver, func(_ netip.AddrPort) {
		workers.Add(2)
		go func() { defer workers.Done(); runWorker(ctx, resolver, "/run/hestia-dns/report.json") }()
		go func() {
			defer workers.Done()
			if err := watchGeneration(ctx, routes, installedBackendConfig, time.Second); err != nil {
				cancel(err)
			}
		}()
	})
	cancel(nil)
	workers.Wait()
	if errors.Is(context.Cause(ctx), errRouteGeneration) {
		return errRouteGeneration
	}
	return err
}

// watchGeneration asks the supervisor for a fresh privileged export when the backend changes.
// Every exchange also checks the generation independently before issuing a DNS request.
func watchGeneration(ctx context.Context, routes *installedRoutes, path string, interval time.Duration) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		if !routes.currentGeneration(path) {
			return errRouteGeneration
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// runWorker starts scheduled refresh and publishes only real observations while the listener is active.
func runWorker(ctx context.Context, resolver *dnsresolver.Resolver, reportPath string) {
	running := make(chan struct{})
	go func() { defer close(running); resolver.Run(ctx, time.Second) }()
	defer func() { <-running; _ = os.Remove(reportPath) }()
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			when, revision, counts, err := resolver.Observations()
			if err != nil {
				_ = os.Remove(reportPath)
				continue
			}
			report := dnspolicy.DNSWarmReport{ObservedAt: when, PolicyRevision: revision, Automatic: make([]dnspolicy.DNSWarmName, 0, len(counts))}
			for _, name := range slices.Sorted(maps.Keys(counts)) {
				report.Automatic = append(report.Automatic, dnspolicy.DNSWarmName{Domain: name, ClientRequests: counts[name]})
			}
			if err = publishReport(reportPath, report); err != nil {
				log.Printf("DNS observation publish: %v", err)
			}
		}
	}
}

// publishReport publishes a complete worker heartbeat readable by the panel's group.
func publishReport(path string, report dnspolicy.DNSWarmReport) error {
	file, err := os.CreateTemp(filepath.Dir(path), ".report-")
	if err != nil {
		return err
	}
	defer os.Remove(file.Name())
	err = json.NewEncoder(file).Encode(report)
	if err == nil {
		err = file.Chmod(0640)
	}
	if err = errors.Join(err, file.Close()); err != nil {
		return err
	}
	return os.Rename(file.Name(), path)
}
