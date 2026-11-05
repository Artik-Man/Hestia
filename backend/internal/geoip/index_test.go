package geoip

import (
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

// TestCountryIndex checks inclusive endpoints, disjoint gaps, both address families and corrupt index rejection.
func TestCountryIndex(t *testing.T) {
	path := filepath.Join(t.TempDir(), "country.bin")
	data := binary.BigEndian.AppendUint32([]byte("HGI1"), 2)
	for _, row := range [][3]string{{"1.1.1.1", "1.1.1.2", "AU"}, {"2.2.2.2", "2.2.2.2", "RU"}, {"2001:123::", "2001:123::3", "FI"}} {
		data = append(data, netip.MustParseAddr(row[0]).AsSlice()...)
		data = append(data, netip.MustParseAddr(row[1]).AsSlice()...)
		data = append(data, row[2]...)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	db, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	for ip, want := range map[string]string{"1.1.1.0": "", "1.1.1.1": "AU", "::ffff:1.1.1.2": "AU", "1.1.1.3": "", "2.2.2.2": "RU", "2001:123::": "FI", "2001:123::3": "FI", "2001:123::4": "", "vk.ru": "", "": ""} {
		if got := db.Country(ip); got != want {
			t.Errorf("%s: got %q want %q", ip, got, want)
		}
	}
	if err := os.WriteFile(path, data[:len(data)-1], 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = Load(path); err == nil {
		t.Fatal("accepted truncated IPv6 range")
	}
}
