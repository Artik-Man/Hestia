//go:build keenetic

package entware

import "encoding/json"

type ingressInboundConfig struct {
	Type          string   `json:"type"`
	Tag           string   `json:"tag"`
	InterfaceName string   `json:"interface_name"`
	AutoRoute     *bool    `json:"auto_route"`
	Address       []string `json:"address"`
}

type ingressBackendConfig struct {
	Inbounds []ingressInboundConfig `json:"inbounds"`
}

// hasManagedIngress validates the exact Hestia inbound profile required before activating the OpkgTun route.
func hasManagedIngress(data []byte) bool {
	var config ingressBackendConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return false
	}
	found := false
	for _, inbound := range config.Inbounds {
		if inbound.Tag != "hestia-keenetic-ingress" {
			continue
		}
		if found || inbound.Type != "tun" || inbound.InterfaceName != "opkgtun0" ||
			inbound.AutoRoute == nil || *inbound.AutoRoute || len(inbound.Address) != 1 || inbound.Address[0] != "172.31.250.2/30" {
			return false
		}
		found = true
	}
	return found
}
