// Package dnsservice connects the router-facing DNS listener to Hestia's installed egress paths.
package dnsservice

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"slices"
	"syscall"
	"time"

	"github.com/Artik-Man/Hestia/internal/binding"
	"github.com/Artik-Man/Hestia/internal/controller"
	"github.com/Artik-Man/Hestia/internal/dnsresolver"
	"github.com/Artik-Man/Hestia/internal/quality"
	"golang.org/x/net/dns/dnsmessage"
)

// installedRoutes contains only transports exported from the current sing-box generation.
type installedRoutes struct {
	Inode     uint64            `json:"inode"`
	Modified  int64             `json:"modified"`
	Paths     []quality.Path    `json:"paths"`
	Resolvers map[string]string `json:"resolvers"`
}

// loadRoutes loads confined egress descriptors and explicit direct-line DNS addresses.
func loadRoutes(path string, direct map[string]string) (*installedRoutes, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var routes installedRoutes
	if err = json.Unmarshal(data, &routes); err != nil || routes.Inode == 0 || routes.Resolvers == nil {
		return nil, errors.New("invalid DNS path export")
	}
	for id, ip := range direct {
		index := slices.IndexFunc(routes.Paths, func(p quality.Path) bool { return p.ID == id })
		if index < 0 || routes.Paths[index].Device == "" || routes.Resolvers[id] != "" {
			return nil, fmt.Errorf("unknown or tunnel DNS override: %s", id)
		}
		routes.Resolvers[id] = ip
	}
	for _, ip := range routes.Resolvers {
		a, err := netip.ParseAddr(ip)
		if err != nil || !a.Is4() || a.IsUnspecified() || a.IsMulticast() || a.IsLoopback() {
			return nil, errors.New("invalid upstream IPv4 address")
		}
	}
	return &routes, nil
}

const installedBackendConfig = "/etc/hestia/sing-box.json"

var errRouteGeneration = errors.New("installed DNS path generation changed")

// currentGeneration compares the path export to the current backend file without reading VPN secrets.
func (r *installedRoutes) currentGeneration(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Sys().(*syscall.Stat_t).Ino == r.Inode && info.ModTime().UnixNano() == r.Modified
}

// Allowed returns only resolver contexts associated with the current trusted selector generation.
func (r *installedRoutes) Allowed(ctx context.Context, name string) ([]dnsresolver.Upstream, error) {
	if !r.currentGeneration(installedBackendConfig) {
		return nil, errRouteGeneration
	}
	data, err := binding.ReadSnapshot()
	if err != nil {
		return nil, err
	}
	cfg, err := controller.CheckSnapshot(data)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	exits, err := controller.DNSExits(ctx, cfg, name)
	if err != nil {
		return nil, err
	}
	if !r.currentGeneration(installedBackendConfig) {
		return nil, errRouteGeneration
	}
	var allowed []dnsresolver.Upstream
	for _, exit := range exits {
		if address := r.Resolvers[exit]; address != "" && slices.ContainsFunc(r.Paths, func(p quality.Path) bool { return p.ID == exit }) {
			allowed = append(allowed, dnsresolver.Upstream{Exit: exit, Resolver: address})
		}
	}
	return allowed, nil
}

// dialAuthorized opens only a permitted exit and rechecks it after the possibly slow dial.
// Revocation during a SOCKS negotiation or TCP handshake closes the socket before any query is sent.
func dialAuthorized(ctx context.Context, p quality.Path, network, target string, allowed func(context.Context) bool) (net.Conn, error) {
	if !allowed(ctx) {
		return nil, errors.New("DNS route withdrawn")
	}
	conn, err := p.DialExit(ctx, network, target)
	if err != nil {
		return nil, err
	}
	if !allowed(ctx) {
		conn.Close()
		return nil, errors.New("DNS route withdrawn before query write")
	}
	deadline, ok := ctx.Deadline()
	if !ok {
		conn.Close()
		return nil, errors.New("DNS exchange requires a deadline")
	}
	if err := conn.SetDeadline(deadline); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// Exchange rechecks authorization for the exact DNS question before using its confined transport.
func (r *installedRoutes) Exchange(ctx context.Context, up dnsresolver.Upstream, packet []byte) ([]byte, error) {
	var question dnsmessage.Message
	if err := question.Unpack(packet); err != nil || len(question.Questions) != 1 {
		return nil, errors.New("invalid upstream question")
	}
	allowed := func(ctx context.Context) bool {
		routes, err := r.Allowed(ctx, question.Questions[0].Name.String())
		return err == nil && slices.Contains(routes, up)
	}
	index := slices.IndexFunc(r.Paths, func(p quality.Path) bool { return p.ID == up.Exit })
	if index < 0 {
		return nil, errors.New("unknown DNS exit")
	}
	ip, err := netip.ParseAddr(up.Resolver)
	if err != nil || !ip.Is4() {
		return nil, errors.New("invalid DNS resolver address")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	target := netip.AddrPortFrom(ip, 53).String()
	p := r.Paths[index]
	conn, err := dialAuthorized(ctx, p, "udp", target, allowed)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if _, err = conn.Write(packet); err != nil {
		return nil, err
	}
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		return nil, err
	}
	var response dnsmessage.Parser
	header, err := response.Start(buf[:n])
	if err != nil || !header.Response || header.ID != question.ID {
		return nil, errors.New("unexpected DNS response")
	}
	if !header.Truncated {
		return buf[:n], nil
	}
	stream, err := dialAuthorized(ctx, p, "tcp", target, allowed)
	if err != nil {
		return nil, err
	}
	defer stream.Close()
	frame := binary.BigEndian.AppendUint16(nil, uint16(len(packet)))
	if _, err = stream.Write(append(frame, packet...)); err != nil {
		return nil, err
	}
	if _, err = io.ReadFull(stream, frame); err != nil {
		return nil, err
	}
	n = int(binary.BigEndian.Uint16(frame))
	_, err = io.ReadFull(stream, buf[:n])
	return buf[:n], err
}
