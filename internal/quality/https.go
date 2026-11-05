package quality

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
)

// probeHTTPS sends one GET over verified TLS to the configured literal destination through the probed exit.
func probeHTTPS(ctx context.Context, p Path, c Check, target string) outcome {
	return fetchHTTPS(ctx, p, c, target, &tls.Config{ServerName: c.ServerName, MinVersion: tls.VersionTLS12})
}

// serviceURL builds an HTTPS origin and request target without triggering DNS resolution.
func serviceURL(c Check, target string) (*url.URL, error) {
	endpoint, err := netip.ParseAddrPort(target)
	if err != nil {
		return nil, err
	}
	u, err := url.ParseRequestURI(c.RequestPath)
	if err != nil {
		return nil, err
	}
	u.Scheme = "https"
	u.Host = c.ServerName
	if endpoint.Port() != 443 {
		u.Host = net.JoinHostPort(c.ServerName, strconv.Itoa(int(endpoint.Port())))
	}
	return u, nil
}

// fetchHTTPS waits for response headers and validates the status; redirects, proxies and alternate dials are disabled.
func fetchHTTPS(ctx context.Context, p Path, c Check, target string, config *tls.Config) outcome {
	u, err := serviceURL(c, target)
	if err != nil {
		return localError
	}
	transport := &http.Transport{
		TLSClientConfig:        config,
		DisableKeepAlives:      true,
		DisableCompression:     true,
		MaxResponseHeaderBytes: 32768,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			conn, err := p.dial(ctx, "tcp", target)
			if err != nil && classify(context.WithoutCancel(ctx), err) == localError {
				return nil, &setupFailure{err}
			}
			return conn, err
		},
	}
	defer transport.CloseIdleConnections()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return localError
	}
	resp, err := transport.RoundTrip(req)
	if err != nil {
		var setup *setupFailure
		if errors.As(err, &setup) || ctx.Err() == context.Canceled {
			return localError
		}
		return failure
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return success
	}
	return failure
}
