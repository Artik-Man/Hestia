package linuxphysical

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/Artik-Man/Hestia/internal/panelmodel"
	"github.com/Artik-Man/Hestia/internal/storage"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"
)

// validateSettings enforces the byte limits of an IEEE 802.11 SSID and a WPA personal passphrase or hexadecimal PSK.
func validateSettings(s panelmodel.WifiConnectionSettings) error {
	if !deviceName.MatchString(s.InterfaceName) || len(s.SSID) == 0 || len(s.SSID) > 32 || !utf8.ValidString(s.SSID) || strings.IndexFunc(s.SSID, unicode.IsControl) >= 0 || s.Band != "2.4" && s.Band != "5" {
		return ErrInvalid
	}
	switch s.Security {
	case "open":
		if s.Password != "" {
			return ErrInvalid
		}
	case "wpa-psk":
		if len(s.Password) == 64 {
			if _, err := hex.DecodeString(s.Password); err != nil {
				return ErrInvalid
			}
		} else if len(s.Password) < 8 || len(s.Password) > 63 || !utf8.ValidString(s.Password) || strings.IndexFunc(s.Password, unicode.IsControl) >= 0 {
			return ErrInvalid
		}
	default:
		return ErrInvalid
	}
	return nil
}

// escapeValue protects GLib keyfile backslashes and leading/trailing spaces in single-line WPA credentials.
func escapeValue(s string) string { return strings.NewReplacer("\\", "\\\\", " ", "\\s").Replace(s) }

// unescapeValue recovers the two GLib escape forms emitted by this writer from a stored passphrase.
func unescapeValue(s string) (string, error) {
	var out strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' {
			out.WriteByte(s[i])
			continue
		}
		i++
		if i >= len(s) {
			return "", ErrConflict
		}
		switch s[i] {
		case '\\':
			out.WriteByte('\\')
		case 's':
			out.WriteByte(' ')
		default:
			return "", ErrConflict
		}
	}
	return out.String(), nil
}

// renderProfile builds a persistent station profile. Private DHCP routes apply only to sockets bound to this adapter.
func renderProfile(id string, s panelmodel.WifiConnectionSettings) []byte {
	sum := sha256.Sum256([]byte("hestia-wifi-routing/" + id))
	table := 100000 + binary.BigEndian.Uint32(sum[:4])%1000000000
	var ssid strings.Builder
	for _, b := range []byte(s.SSID) {
		fmt.Fprintf(&ssid, "%d;", b)
	}
	band := "bg"
	if s.Band == "5" {
		band = "a"
	}
	security := ""
	if s.Security == "wpa-psk" {
		security = "\n[wifi-security]\nkey-mgmt=wpa-psk\npsk=" + escapeValue(s.Password) + "\n"
	}
	return []byte(fmt.Sprintf("[connection]\nid=hestia-wifi-%s\nuuid=%s\ntype=wifi\ninterface-name=%s\nautoconnect=true\n\n[wifi]\nmode=infrastructure\nband=%s\nssid=%s\n%s\n[ipv4]\nmethod=auto\nmay-fail=false\nignore-auto-dns=true\nroute-table=%d\nrouting-rule1=priority 22000 oif %s table %d\n\n[ipv6]\nmethod=disabled\n", id, id, s.InterfaceName, band, ssid.String(), security, table, s.InterfaceName, table))
}

// decodeSSID accepts NM's semicolon-separated byte representation or its printable string representation.
func decodeSSID(value string) (string, error) {
	if strings.HasSuffix(value, ";") {
		parts := strings.Split(strings.TrimSuffix(value, ";"), ";")
		bytes := make([]byte, 0, len(parts))
		for _, part := range parts {
			n, err := strconv.ParseUint(part, 10, 8)
			if err != nil {
				return unescapeValue(value)
			}
			bytes = append(bytes, byte(n))
		}
		return string(bytes), nil
	}
	return unescapeValue(value)
}

// readProfile reads only root-private, regular profiles with the expected managed name and UUID. Raw bytes are for rollback only.
func (m Manager) readProfile(id string) (panelmodel.WifiConnection, []byte, error) {
	var record panelmodel.WifiConnection
	_, dir := m.paths()
	path := filepath.Join(dir, wifiFilename(id))
	f, err := storage.OpenFile(path, storage.ReadOnly|storage.NoFollow|storage.Nonblock, 0)
	if errors.Is(err, os.ErrNotExist) {
		return record, nil, ErrNotFound
	}
	if storage.IsSymlink(err) {
		return record, nil, ErrConflict
	}
	if err != nil {
		return record, nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return record, nil, err
	}
	stat, ok := storage.Stat(info)
	if !ok || stat.Uid != m.ownerUID || stat.Nlink != 1 || !info.Mode().IsRegular() || info.Mode().Perm()&0077 != 0 || info.Size() > 64<<10 {
		return record, nil, ErrConflict
	}
	data, err := io.ReadAll(io.LimitReader(f, 65537))
	if err != nil || len(data) > 65536 {
		return record, nil, ErrConflict
	}
	values := keyValues(data)
	if values["connection.uuid"] != id || values["connection.id"] != "hestia-wifi-"+id || values["connection.type"] != "wifi" && values["connection.type"] != "802-11-wireless" {
		return record, nil, ErrConflict
	}
	record.ID, record.InterfaceName = id, values["connection.interface-name"]
	record.SSID, err = decodeSSID(values["wifi.ssid"])
	if err != nil {
		return record, nil, err
	}
	record.Band = map[string]string{"bg": "2.4", "a": "5"}[values["wifi.band"]]
	record.Security = "open"
	if value := values["wifi-security.key-mgmt"]; value != "" {
		if value != "wpa-psk" {
			return record, nil, ErrConflict
		}
		record.Security = value
	}
	if record.Band == "" || record.SSID == "" || !deviceName.MatchString(record.InterfaceName) {
		return record, nil, ErrConflict
	}
	return record, data, nil
}

// keyValues indexes individual keys from a bounded local keyfile while keeping each value's significant trailing spaces.
func keyValues(data []byte) map[string]string {
	values := map[string]string{}
	section := ""
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.Trim(line, "[]")
			continue
		}
		key, value, ok := strings.Cut(line, "=")
		if ok {
			values[section+"."+key] = value
		}
	}
	return values
}

// writePrivate atomically installs a fully flushed private keyfile beside its previous version.
func writePrivate(path string, data []byte) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".hestia-wifi-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), path)
}
