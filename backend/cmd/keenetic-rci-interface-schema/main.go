// Command keenetic-rci-interface-schema reads interface inventory via RCI and emits only bounded JSON shape metadata.
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

var safeInterfaceFields = []string{
	"id", "type", "link", "connected", "state", "speed", "duplex", "description",
	"index", "defaultgw", "priority", "interface-name", "name", "ssid", "essid",
	"band", "frequency", "channel",
}

// output contains only the requested operation metadata, response digest, and anonymized JSON shape.
type output struct {
	Request  requestMetadata              `json:"request"`
	Response keeneticrci.ResponseMetadata `json:"response"`
	Schema   keeneticrci.SchemaNode       `json:"schema"`
	RawSaved bool                         `json:"raw_response_saved"`
}

// requestMetadata identifies the fixed read-only interface inventory operation without exposing the token or response values.
type requestMetadata struct {
	Method string `json:"method"`
	Path   string `json:"path"`
}

// main performs one authenticated GET /rci/show/interface and prints only its safe structural description.
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
		fail("invalid_client_config")
	}
	response, err := client.Do(context.Background(), keeneticrci.Operation{
		Name:   "read_interface_schema",
		Path:   "/rci/show/interface",
		Method: keeneticrci.MethodGet,
	}, nil)
	if err != nil {
		fail("rci_request_failed")
	}
	schema, err := keeneticrci.DescribeSchema(response.Body, safeInterfaceFields)
	if err != nil {
		fail("response_schema_unavailable")
	}
	result := output{
		Request:  requestMetadata{Method: "GET", Path: "/rci/show/interface"},
		Response: keeneticrci.ResponseMetadata{Status: response.Status, ContentType: response.ContentType, BodyBytes: response.BodyBytes, BodySHA256: response.BodySHA256},
		Schema:   schema,
		RawSaved: false,
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

// fail emits a stable error code and never prints request credentials or response bytes.
func fail(code string) {
	_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"result": "failed", "error": code})
	fmt.Fprintln(os.Stderr, "Keenetic RCI interface schema request failed")
	os.Exit(1)
}
