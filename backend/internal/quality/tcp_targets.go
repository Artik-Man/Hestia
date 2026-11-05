package quality

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/Artik-Man/Hestia/internal/netaddress"
	"golang.org/x/net/dns/dnsmessage"
)

// NormalizeTCPInput converts editor entries to public literal endpoints in input order, defaulting
// omitted ports to 443. Each distinct domain costs at most one A query per call. Other protocols
// pass through; an error leaves the original targets intact. An empty server uses the gateway's resolver.
func (c *QualityCheck) NormalizeTCPInput(ctx context.Context, server string) error {
	if c.Protocol != TCP {
		return nil
	}
	if len(c.Targets) < 1 || len(c.Targets) > 8 {
		return errors.New("для проверки требуется от одной до восьми целей")
	}
	resolved := make(map[string]netip.Addr)
	targets := make([]string, 0, len(c.Targets))
	for _, raw := range c.Targets {
		host, port, err := tcpInputHostPort(raw)
		if err != nil {
			return err
		}
		ip, err := netip.ParseAddr(host)
		if err != nil {
			name := strings.ToLower(strings.TrimSuffix(host, "."))
			if !validName(host) || strings.Trim(name, "0123456789.") == "" {
				return fmt.Errorf("некорректный IP-адрес или домен TCP: %q", host)
			}
			var found bool
			if ip, found = resolved[name]; !found {
				if server == "" {
					server, err = systemNameserver()
					if err != nil {
						return fmt.Errorf("DNS для %s: %w", host, err)
					}
				}
				ip, err = queryPublicIPv4(ctx, server, name)
				if err != nil {
					return fmt.Errorf("DNS для %s: %w", host, err)
				}
				resolved[name] = ip
			}
		}
		if !netaddress.Public(ip.Unmap()) {
			return fmt.Errorf("цель TCP %q: требуется публичный IP-адрес", host)
		}
		targets = append(targets, netip.AddrPortFrom(ip.Unmap(), port).String())
	}
	c.Targets = targets
	return nil
}

// tcpInputHostPort separates DNS names and IP literals from optional decimal ports; bare IPv6 uses port 443.
func tcpInputHostPort(raw string) (string, uint16, error) {
	target := strings.TrimSpace(raw)
	if _, err := netip.ParseAddr(target); err == nil || !strings.Contains(target, ":") {
		return target, 443, nil
	}
	if endpoint, err := netip.ParseAddrPort(target); err == nil && endpoint.Port() != 0 {
		return endpoint.Addr().String(), endpoint.Port(), nil
	}
	host, port, ok := strings.Cut(target, ":")
	number, err := strconv.ParseUint(port, 10, 16)
	if !ok || err != nil || number == 0 || strings.ContainsAny(host, "[]") {
		return "", 0, fmt.Errorf("некорректная цель TCP %q: укажите IP или домен и порт от 1 до 65535", raw)
	}
	return host, uint16(number), nil
}

// systemNameserver selects the first literal resolver from the gateway's resolver configuration.
func systemNameserver() (string, error) {
	data, err := os.ReadFile("/etc/resolv.conf")
	if err != nil {
		return "", errors.New("не удалось прочитать настройки DNS-сервера")
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		line, _, _ = strings.Cut(line, "#")
		fields := strings.Fields(line)
		if len(fields) >= 2 && fields[0] == "nameserver" {
			if addr, err := netip.ParseAddr(fields[1]); err == nil {
				return netip.AddrPortFrom(addr, 53).String(), nil
			}
		}
	}
	return "", errors.New("не настроен DNS-сервер")
}

// queryPublicIPv4 sends exactly one A question over connected UDP, with no fallback, retry or search suffix.
func queryPublicIPv4(parent context.Context, server, name string) (netip.Addr, error) {
	ctx, cancel := context.WithTimeout(parent, 3*time.Second)
	defer cancel()
	query, packet, err := makeAQuery(name)
	if err != nil {
		return netip.Addr{}, err
	}
	conn, err := new(net.Dialer).DialContext(ctx, "udp", server)
	if err != nil {
		return netip.Addr{}, errors.New("не удалось подключиться к DNS-серверу")
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return netip.Addr{}, err
	}
	if _, err := conn.Write(packet); err != nil {
		return netip.Addr{}, errors.New("не удалось отправить DNS-запрос")
	}
	buf := make([]byte, 65535)
	for {
		n, err := conn.Read(buf)
		if err != nil {
			if errors.Is(err, os.ErrDeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded) {
				return netip.Addr{}, errors.New("истёк тайм-аут ответа DNS-сервера")
			}
			return netip.Addr{}, errors.New("не удалось получить ответ DNS-сервера")
		}
		var answer dnsmessage.Message
		if answer.Unpack(buf[:n]) != nil || !matchesQuery(&answer, &query) {
			continue
		}
		if answer.Truncated {
			return netip.Addr{}, errors.New("DNS-сервер вернул усечённый ответ")
		}
		switch answer.RCode {
		case dnsmessage.RCodeNameError:
			return netip.Addr{}, errors.New("домен не найден (NXDOMAIN)")
		case dnsmessage.RCodeSuccess:
			if ip, ok := firstAnswerIPv4(&answer, netaddress.Public); ok {
				return ip, nil
			}
			return netip.Addr{}, errors.New("в ответе нет допустимого публичного IPv4-адреса")
		default:
			return netip.Addr{}, fmt.Errorf("ошибка ответа DNS-сервера (%s)", answer.RCode)
		}
	}
}
