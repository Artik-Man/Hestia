package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/Artik-Man/Hestia/pkg/keeneticrci"
)

type item struct {
	Path    string           `json:"path"`
	Error   string           `json:"error,omitempty"`
	Status  int              `json:"status"`
	Bytes   int64            `json:"bytes"`
	SHA256  string           `json:"sha256"`
	Matches []map[string]any `json:"matches,omitempty"`
}

var fields = map[string]bool{"id": true, "name": true, "description": true, "type": true, "link": true, "connected": true, "state": true, "interface": true, "interface-name": true, "defaultgw": true, "priority": true, "destination": true, "network": true, "prefix": true, "metric": true, "route": true, "device": true, "dev": true, "next-hop": true}

// main sends two fixed read-only RCI GET requests and prints an allowlisted response projection.
func main() {
	token := flag.String("token-file", filepath.Join(os.Getenv("HOME"), ".config/hestia/keenetic-rci-token"), "token file")
	base := flag.String("base-url", "http://127.0.0.1:17979", "loopback RCI URL")
	flag.Parse()
	c, e := keeneticrci.NewClient(keeneticrci.Config{BaseURL: *base, TokenSource: keeneticrci.FileTokenSource{Path: *token}, Timeout: 10 * time.Second})
	if e != nil {
		fmt.Println(`{"error":"client_config"}`)
		os.Exit(1)
	}
	paths := []string{"/rci/show/interface", "/rci/show/ip/route"}
	outs := make([]item, 0, len(paths))
	for _, p := range paths {
		r, e := c.Do(context.Background(), keeneticrci.Operation{Name: "read_only_probe", Path: p, Method: keeneticrci.MethodGet}, nil)
		if e != nil {
			k := "request_failed"
			if ce, ok := e.(*keeneticrci.Error); ok {
				k = string(ce.Kind)
			}
			outs = append(outs, item{Path: p, Error: k})
			continue
		}
		x := item{Path: p, Status: r.Status, Bytes: r.BodyBytes, SHA256: r.BodySHA256}
		var v any
		if json.Unmarshal(r.Body, &v) == nil {
			walk(v, "", &x.Matches)
		}
		outs = append(outs, x)
	}
	_ = json.NewEncoder(os.Stdout).Encode(outs)
}

// walk visits decoded RCI JSON and retains only allowlisted fields from objects containing a target identifier.
func walk(v any, path string, out *[]map[string]any) {
	switch x := v.(type) {
	case map[string]any:
		safe := map[string]any{}
		relevant := false
		for k, val := range x {
			if s, ok := val.(string); ok && (s == "ПАКТ" || s == "eth2" || s == "eth3" || s == "GigabitEthernet1/0" || s == "0.0.0.0/0" || s == "default") {
				relevant = true
			}
			if fields[k] {
				switch val.(type) {
				case string, float64, bool:
					safe[k] = val
				}
			}
		}
		if relevant && len(safe) > 0 {
			safe["json_path"] = path
			*out = append(*out, safe)
		}
		for k, val := range x {
			walk(val, path+"/"+k, out)
		}
	case []any:
		for i, val := range x {
			walk(val, fmt.Sprintf("%s/%d", path, i), out)
		}
	}
}
