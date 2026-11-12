package controller

import "github.com/Artik-Man/Hestia/internal/awghealth"

// AWGHeartbeatHealthy reports whether the named connector has a fresh verified runtime heartbeat.
func AWGHeartbeatHealthy(id string) bool {
	return awghealth.HeartbeatHealthy(id)
}

// AWGTransportHealth returns the verified active transport and freshness of one connector heartbeat.
func AWGTransportHealth(id string) (string, bool) {
	return awghealth.TransportHealth(id)
}
