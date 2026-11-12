// Command keenetic-rci-wisp-status reads redacted WISP station status through the shared RCI client.
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

// output contains only typed operational station fields and safe transport metadata.
type output struct {
	Interfaces []keeneticrci.WISPInterface  `json:"interfaces"`
	Response   keeneticrci.ResponseMetadata `json:"response"`
}

// main performs one bounded read-only query and prints only the connector's redacted result.
func main() {
	baseURL := flag.String("base-url", "http://127.0.0.1:79", "RCI endpoint (HTTP loopback or HTTPS)")
	tokenPath := flag.String("token-file", defaultTokenPath(), "owner-only RCI token file")
	timeout := flag.Duration("timeout", 10*time.Second, "maximum request duration")
	flag.Parse()
	if flag.NArg() != 0 {
		fail("invalid_arguments")
	}
	client, err := keeneticrci.NewClient(keeneticrci.Config{
		BaseURL:     *baseURL,
		TokenSource: keeneticrci.FileTokenSource{Path: *tokenPath},
		Timeout:     *timeout,
	})
	if err != nil {
		fail("invalid_client_config")
	}
	connector, err := keeneticrci.NewWISPConnector(client)
	if err != nil {
		fail("invalid_connector_config")
	}
	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	inventory, err := connector.Read(ctx)
	if err != nil {
		fail("rci_request_or_schema_failed")
	}
	result := output{
		Interfaces: inventory.Interfaces,
		Response:   inventory.Response,
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fail("output_failed")
	}
}

// defaultTokenPath resolves the standard owner token location without reading or printing its contents.
func defaultTokenPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".config", "hestia", "keenetic-rci-token")
	}
	return filepath.Join(home, ".config", "hestia", "keenetic-rci-token")
}

// fail emits only a stable error code and never prints credentials or raw RCI response data.
func fail(code string) {
	_, _ = fmt.Fprintln(os.Stderr, "Keenetic WISP status query failed:", code)
	os.Exit(1)
}
