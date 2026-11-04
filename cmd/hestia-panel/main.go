// Command hestia-panel serves the local panel and can apply list bindings on an installed gateway.
package main

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/Artik-Man/Hestia/internal/binding"
	"github.com/Artik-Man/Hestia/internal/controller"
	"github.com/Artik-Man/Hestia/internal/panelmodel"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humago"
)

const installedSnapshot = "/etc/hestia/snapshot.json"

// sameSnapshotPath recognizes alternate spellings and symlinks to the managed snapshot.
func sameSnapshotPath(path, installed string) bool {
	actual, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	if actual == installed {
		return true
	}
	resolved, err := filepath.EvalSymlinks(actual)
	if err != nil {
		return false
	}
	expected, err := filepath.EvalSymlinks(installed)
	return err == nil && resolved == expected
}

// readSnapshot reads and validates the current file without contacting a selector.
// Arrays retain controller order and encode empty collections as JSON arrays.
func readSnapshot(path string, managed bool) (panelmodel.Snapshot, error) {
	var data []byte
	var err error
	if !managed && sameSnapshotPath(path, installedSnapshot) {
		// Legacy installers have no transaction lock for readers. New installations must use it
		// even if this panel only reads while another panel is applying a change.
		_, statErr := os.Stat("/etc/tmpfiles.d/hestia-binding.conf")
		managed = !os.IsNotExist(statErr)
	}
	if managed {
		data, err = binding.ReadSnapshot()
	} else {
		data, err = os.ReadFile(path)
	}
	if err != nil {
		return panelmodel.Snapshot{}, err
	}
	cfg, err := controller.CheckSnapshot(data)
	if err != nil {
		return panelmodel.Snapshot{}, err
	}
	view := panelmodel.Snapshot{Groups: make([]panelmodel.Group, len(cfg.Groups)), Lists: make([]panelmodel.RuleList, len(cfg.Lists))}
	for i, g := range cfg.Groups {
		exits := make([]panelmodel.Exit, len(g.Exits))
		for j, id := range g.Exits {
			exits[j] = panelmodel.Exit{ID: id, Available: cfg.Healthy[id]}
		}
		view.Groups[i] = panelmodel.Group{ID: g.ID, IsDefault: i == 0, Exits: exits}
	}
	for i, l := range cfg.Lists {
		view.Lists[i] = panelmodel.RuleList{ID: l.ID, Group: l.Group, Enabled: l.Group != "", Masks: append([]string{}, l.Masks...)}
	}
	return view, nil
}

// readAssets copies public browser resources from a trusted build directory at startup.
// Symlinks, dotfiles and non-browser formats are excluded; a missing index aborts startup.
func readAssets(dir string) (map[string][]byte, error) {
	assets := map[string][]byte{}
	bundle := os.DirFS(dir)
	err := fs.WalkDir(bundle, ".", func(name string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if name != "." && strings.HasPrefix(entry.Name(), ".") {
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if !entry.Type().IsRegular() {
			return nil
		}
		if name != "index.html" && !slices.Contains([]string{".js", ".css", ".svg", ".png", ".ico", ".woff", ".woff2", ".ttf"}, filepath.Ext(name)) {
			return nil
		}
		data, err := fs.ReadFile(bundle, name)
		if err != nil {
			return err
		}
		assets[name] = data
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(assets["index.html"]) == 0 {
		return nil, fmt.Errorf("missing or empty index.html in %s", dir)
	}
	return assets, nil
}

// snapshotOutput describes the successful JSON response for the registered operation.
type snapshotOutput struct {
	Body panelmodel.Snapshot
}

// navigationOutput describes the navigation settings response for code generation.
type navigationOutput struct {
	Body panelmodel.Navigation
}

// registerPanelAPI registers the same typed operations for the live mux and OpenAPI generation.
func registerPanelAPI(mux *http.ServeMux, snapshot, grafanaURL string, writes panelWrites) huma.API {
	config := huma.DefaultConfig("Локальная панель Гестии", "1.0.0")
	config.Servers = []*huma.Server{{URL: "/"}}
	// Only registered panel operations are public. Their bodies are the unmodified DTOs.
	config.OpenAPIPath, config.SchemasPath, config.DocsPath = "", "", ""
	config.CreateHooks = nil
	api := humago.New(mux, config)
	api.UseMiddleware(func(ctx huma.Context, next func(huma.Context)) {
		ctx.SetHeader("Cache-Control", "no-store")
		next(ctx)
	})
	huma.Register(api, huma.Operation{
		OperationID: "getGroupsAndRules", Tags: []string{"Panel"}, Method: http.MethodGet, Path: "/api/groups-and-rules",
		Summary: "Прочитать проверенный снимок групп и доменных списков", Errors: []int{http.StatusServiceUnavailable},
	}, func(_ context.Context, _ *struct{}) (*snapshotOutput, error) {
		view, err := readSnapshot(snapshot, writes.binding != nil || writes.order != nil)
		if err != nil {
			log.Printf("cannot load snapshot: %v", err)
			return nil, huma.Error503ServiceUnavailable("Снимок конфигурации недоступен")
		}
		return &snapshotOutput{Body: view}, nil
	})
	huma.Register(api, huma.Operation{
		OperationID: "getNavigation", Tags: []string{"Panel"}, Method: http.MethodGet, Path: "/api/navigation",
		Summary: "Прочитать настройки внешних ссылок панели",
	}, func(_ context.Context, _ *struct{}) (*navigationOutput, error) {
		return &navigationOutput{Body: panelmodel.Navigation{GrafanaURL: grafanaURL}}, nil
	})
	registerBinding(api, writes.binding)
	registerOrder(api, writes.order)
	registerAWG(api, writes.awg)
	return api
}

// writeOpenAPI exports the same registered operations used at runtime as OpenAPI 3.0.3 for Angular generation.
func writeOpenAPI(path string) error {
	api := registerPanelAPI(http.NewServeMux(), "", "", panelWrites{})
	data, err := api.OpenAPI().DowngradeYAML()
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// panelHandler serves local assets and the typed panel API. It rejects cross-origin browser mutations.
func panelHandler(snapshot, grafanaURL string, assets map[string][]byte, writes panelWrites) http.Handler {
	mux := http.NewServeMux()
	registerPanelAPI(mux, snapshot, grafanaURL, writes)
	mux.HandleFunc("GET /", func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/")
		switch name {
		case "", "groups-and-rules", "connections":
			name = "index.html"
		}
		data, ok := assets[name]
		if !ok {
			http.NotFound(w, r)
			return
		}
		if name == "index.html" {
			w.Header().Set("Cache-Control", "no-cache")
		}
		http.ServeContent(w, r, name, time.Time{}, bytes.NewReader(data))
	})
	return http.NewCrossOriginProtection().Handler(mux)
}

// localHandler rejects browser requests addressed to another host, including DNS rebinding.
// The listener is restricted to a specific private or loopback address.
func localHandler(listen string, next http.Handler) (http.Handler, error) {
	host, _, err := net.SplitHostPort(listen)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	if !ip.IsLoopback() && !ip.IsPrivate() {
		return nil, fmt.Errorf("listen on a specific loopback or private LAN IP")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := r.Host
		if hostname, _, err := net.SplitHostPort(h); err == nil {
			h = hostname
		}
		if !(h == "localhost" && ip.IsLoopback()) && !ip.Equal(net.ParseIP(strings.Trim(h, "[]"))) {
			http.Error(w, "Unknown host", http.StatusForbidden)
			return
		}
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self' data:; frame-ancestors 'none'; base-uri 'self'; object-src 'none'")
		next.ServeHTTP(w, r)
	}), nil
}

// validateGrafanaURL accepts an empty setting or an absolute HTTPS link without credentials.
// The administrator selects the destination explicitly. Startup never probes it.
func validateGrafanaURL(value string) error {
	if value == "" {
		return nil
	}
	u, err := url.Parse(value)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" || u.User != nil || strings.Contains(value, "\\") || strings.ContainsRune(value, '\uFEFF') || strings.IndexFunc(value, unicode.IsSpace) >= 0 {
		return fmt.Errorf("grafana-url must be an absolute HTTPS URL without credentials or whitespace")
	}
	if port := u.Port(); port != "" {
		p, err := strconv.ParseUint(port, 10, 16)
		if err != nil || p == 0 {
			return fmt.Errorf("invalid grafana-url port")
		}
	}
	return nil
}

// main loads the browser bundle once and starts the HTTP listener. Snapshot errors remain retryable.
func main() {
	listen := flag.String("listen", "127.0.0.1:8080", "private LAN or loopback IP and port")
	snapshot := flag.String("snapshot", "", "controller snapshot file (required)")
	assets := flag.String("assets", "", "browser build directory containing index.html (required)")
	grafanaURL := flag.String("grafana-url", "", "optional trusted HTTPS URL for the Grafana menu link")
	enableOrder := flag.Bool("enable-group-order", false, "enable confirmed group and exit ordering on the installed gateway")
	enableBindings := flag.Bool("enable-bindings", false, "enable confirmed list binding changes on the installed gateway")
	enableAWG := flag.Bool("enable-awg", false, "enable privileged AmneziaWG profile management on the installed gateway")
	openapi := flag.String("openapi", "", "write the generated OpenAPI contract at this path and exit")
	flag.Parse()
	if *openapi != "" {
		if err := writeOpenAPI(*openapi); err != nil {
			log.Fatal(err)
		}
		return
	}
	if *snapshot == "" || *assets == "" {
		flag.Usage()
		os.Exit(2)
	}
	if err := validateGrafanaURL(*grafanaURL); err != nil {
		log.Fatal(err)
	}
	bundle, err := readAssets(*assets)
	if err != nil {
		log.Fatal(err)
	}
	var writes panelWrites
	if (*enableBindings || *enableOrder || *enableAWG) && *snapshot != installedSnapshot {
		log.Fatal("routing changes require /etc/hestia/snapshot.json")
	}
	if *enableBindings {
		writes.binding = applyInstalledBinding
	}
	if *enableOrder {
		writes.order = applyInstalledOrder
	}
	if *enableAWG {
		writes.awg = installedAWGWriter{}
	}
	h, err := localHandler(*listen, panelHandler(*snapshot, *grafanaURL, bundle, writes))
	if err != nil {
		log.Fatal(err)
	}
	server := &http.Server{Addr: *listen, Handler: h, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 10 * time.Second, WriteTimeout: 5 * time.Minute, IdleTimeout: 60 * time.Second}
	log.Printf("serving Hestia panel on %s", server.Addr)
	log.Fatal(server.ListenAndServe())
}
