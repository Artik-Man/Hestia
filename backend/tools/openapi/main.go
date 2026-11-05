// Command openapi writes the registered gateway API contract on the development host.
package main

import (
	"flag"
	"log"

	"github.com/Artik-Man/Hestia/internal/panel"
)

// main writes the contract to the specified path and exits on error.
func main() {
	output := flag.String("output", "api/openapi.yaml", "output file for the generated OpenAPI contract")
	flag.Parse()
	if err := panel.WriteOpenAPI(*output); err != nil {
		log.Fatal(err)
	}
}
