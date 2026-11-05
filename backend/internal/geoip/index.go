// Package geoip reads the country ranges shared with the gateway routing rules.
package geoip

import (
	"bytes"
	_ "embed"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sort"
	"strings"
)

// CountryCodes contains the ISO 3166-1 alpha-2 catalogue shared with the policy and importer.
//
//go:embed countries.txt
var CountryCodes string

// Index owns immutable IPv4 and IPv6 inclusive ranges sorted by numeric address.
type Index struct {
	v4, v6 []byte
}

// Load opens and validates a DB-IP import produced by deploy/import_geoip.py.
func Load(path string) (*Index, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) < 8 || string(data[:4]) != "HGI1" {
		return nil, errors.New("invalid GeoIP index header")
	}
	split := 8 + int64(binary.BigEndian.Uint32(data[4:8]))*10
	if split > int64(len(data)) {
		return nil, errors.New("truncated IPv4 GeoIP index")
	}
	db := &Index{v4: data[8:split], v6: data[split:]}
	countries := make(map[string]bool)
	for _, code := range strings.Fields(CountryCodes) {
		countries[code] = true
	}
	if len(data) == 8 || !validRanges(db.v4, 4, countries) || !validRanges(db.v6, 16, countries) {
		return nil, fmt.Errorf("invalid GeoIP ranges in %s", path)
	}
	return db, nil
}

// validRanges requires complete records with disjoint ordered endpoints and supported codes.
func validRanges(records []byte, width int, countries map[string]bool) bool {
	stride := 2*width + 2
	if len(records)%stride != 0 {
		return false
	}
	var previous []byte
	for len(records) > 0 {
		first, last := records[:width], records[width:2*width]
		if bytes.Compare(first, previous) <= 0 || bytes.Compare(first, last) > 0 || !countries[string(records[2*width:stride])] {
			return false
		}
		previous = last
		records = records[stride:]
	}
	return true
}

// Country looks up a numeric destination in the current data; an absent index or unknown address yields "".
func (db *Index) Country(address string) string {
	addr, err := netip.ParseAddr(address)
	if db == nil || err != nil || addr.Zone() != "" {
		return ""
	}
	key := addr.Unmap().AsSlice()
	records := db.v6
	if len(key) == 4 {
		records = db.v4
	}
	width := len(key)
	stride := 2*width + 2
	i := sort.Search(len(records)/stride, func(i int) bool {
		return bytes.Compare(records[i*stride+width:i*stride+2*width], key) >= 0
	})
	offset := i * stride
	if offset == len(records) || bytes.Compare(records[offset:offset+width], key) > 0 {
		return ""
	}
	return string(records[offset+2*width : offset+stride])
}
