// Command keenetic-rci-survey-schema reads one Wi-Fi survey through RCI and emits only response structure metadata.
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

var safeSurveyFields = []string{
	"site-survey", "name", "essid", "ssid", "mac", "bssid", "channel", "frequency",
	"rate", "quality", "mode", "q", "signal", "security", "encryption", "networks",
	"results", "result", "data", "status",
}

// output contains bounded request metadata and a privacy-preserving description of the JSON shape.
type output struct {
	Request  requestMetadata              `json:"request"`
	Response keeneticrci.ResponseMetadata `json:"response"`
	Schema   keeneticrci.SchemaNode       `json:"schema"`
}

// requestMetadata describes the request without including credentials or the selected radio value.
type requestMetadata struct {
	Method string `json:"method"`
	Path   string `json:"path"`
	Radio  string `json:"radio"`
}

// schemaNode describes JSON structure without storing scalar values or arbitrary object keys.
type schemaNode struct {
	Type        string       `json:"type"`
	ArrayLength *int         `json:"array_length,omitempty"`
	Fields      []schemaNode `json:"fields,omitempty"`
	Name        string       `json:"name,omitempty"`
	OtherFields int          `json:"other_fields,omitempty"`
}

// main reads a single allowlisted radio and prints only safe RCI and response-schema metadata.
func main() {
	baseURL := flag.String("base-url", "http://127.0.0.1:79", "RCI endpoint (HTTP loopback or HTTPS)")
	tokenPath := flag.String("token-file", defaultTokenPath(), "owner-only RCI token file")
	radio := flag.String("radio", "", "radio interface to scan: WifiMaster0 or WifiMaster1")
	timeout := flag.Duration("timeout", 20*time.Second, "maximum request duration")
	flag.Parse()
	if flag.NArg() != 0 || (*radio != "WifiMaster0" && *radio != "WifiMaster1") {
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
	requestBody, err := json.Marshal([]map[string]map[string]string{{"site-survey": {"name": *radio}}})
	if err != nil {
		fail("request_encoding_failed")
	}
	response, err := client.Do(context.Background(), keeneticrci.Operation{
		Name:   "read_site_survey_schema",
		Path:   "/rci/show",
		Method: keeneticrci.MethodPost,
	}, requestBody)
	if err != nil {
		fail("rci_request_failed")
	}
	shape, err := keeneticrci.DescribeSchema(response.Body, safeSurveyFields)
	if err != nil {
		fail("response_schema_unavailable")
	}
	result := output{
		Request:  requestMetadata{Method: "POST", Path: "/rci/show", Radio: *radio},
		Response: keeneticrci.ResponseMetadata{Status: response.Status, ContentType: response.ContentType, BodyBytes: response.BodyBytes, BodySHA256: response.BodySHA256},
		Schema:   shape,
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

// fail emits only a stable error code so transport errors and response data stay private.
func fail(code string) {
	_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"result": "failed", "error": code})
	fmt.Fprintln(os.Stderr, "Keenetic RCI survey schema request failed")
	os.Exit(1)
}
