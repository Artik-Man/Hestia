// Command keenetic-rci-ethernet reads a sanitized Ethernet inventory through Keenetic RCI.
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

// output is the allowlisted JSON record emitted by this research command.
type output struct {
	TimeUTC  string                       `json:"time_utc"`
	Request  requestMetadata              `json:"request"`
	Response keeneticrci.ResponseMetadata `json:"response"`
	Ports    []keeneticrci.EthernetPort   `json:"ports"`
	RawSaved bool                         `json:"raw_response_saved"`
}

// requestMetadata describes the operation without exposing credentials or response contents.
type requestMetadata struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

// main reads and emits only the typed Ethernet port fields returned by the connector.
func main() {
	baseURL := flag.String("base-url", "http://127.0.0.1:79", "RCI endpoint (HTTP loopback or HTTPS)")
	tokenPath := flag.String("token-file", defaultTokenPath(), "owner-only RCI token file")
	timeout := flag.Duration("timeout", 10*time.Second, "maximum request duration")
	flag.Parse()

	if flag.NArg() != 0 {
		fail("unexpected_arguments")
	}
	client, err := keeneticrci.NewClient(keeneticrci.Config{
		BaseURL:     *baseURL,
		TokenSource: keeneticrci.FileTokenSource{Path: *tokenPath},
		Timeout:     *timeout,
	})
	if err != nil {
		fail(err.Error())
	}
	connector, err := keeneticrci.NewEthernetConnector(client)
	if err != nil {
		fail(err.Error())
	}
	inventory, err := connector.Read(context.Background())
	if err != nil {
		fail(err.Error())
	}
	result := output{
		TimeUTC:  time.Now().UTC().Format(time.RFC3339),
		Request:  requestMetadata{Method: "GET", Path: "/rci/show/interface"},
		Response: inventory.Response,
		Ports:    inventory.Ports,
		RawSaved: false,
	}
	if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
		fail("output_failed")
	}
}

// defaultTokenPath resolves the standard Hestia token location under the current user's home.
func defaultTokenPath() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return filepath.Join(".config", "hestia", "keenetic-rci-token")
	}
	return filepath.Join(home, ".config", "hestia", "keenetic-rci-token")
}

// fail emits a redacted JSON error and exits without printing HTTP bodies or credentials.
func fail(reason string) {
	_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"result": "failed", "error": reason})
	fmt.Fprintln(os.Stderr, "Keenetic RCI request failed")
	os.Exit(1)
}
