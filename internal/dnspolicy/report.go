package dnspolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"syscall"
	"time"
)

// DNSWarmName records the measured client demand for one automatically selected name.
type DNSWarmName struct {
	Domain         string `json:"domain" minLength:"1" maxLength:"253"`
	ClientRequests int    `json:"clientRequests" minimum:"1"`
}

// DNSWarmReport identifies when and under which policy the DNS worker observed automatic membership.
type DNSWarmReport struct {
	ObservedAt     time.Time     `json:"observedAt"`
	PolicyRevision int           `json:"policyRevision" minimum:"0"`
	Automatic      []DNSWarmName `json:"automatic" nullable:"false"`
}

// MaxReportNames bounds an automatic membership snapshot accepted from the DNS worker.
const MaxReportNames = 32768

// ReadWarmReport returns an entire fresh, validated worker snapshot. An absent, incomplete,
// oversized or stale heartbeat is unavailable even when an earlier report was valid.
func ReadWarmReport(path string, now time.Time) (DNSWarmReport, error) {
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if err != nil {
		return DNSWarmReport{}, err
	}
	defer file.Close()
	const maximum = 10 << 20
	info, err := file.Stat()
	if err != nil {
		return DNSWarmReport{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > maximum {
		return DNSWarmReport{}, errors.New("invalid DNS report file")
	}
	data, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil {
		return DNSWarmReport{}, err
	}
	if len(data) > maximum {
		return DNSWarmReport{}, errors.New("DNS report exceeds size limit")
	}
	var wire struct {
		ObservedAt     time.Time     `json:"observedAt"`
		PolicyRevision *int          `json:"policyRevision"`
		Automatic      []DNSWarmName `json:"automatic"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&wire); err != nil {
		return DNSWarmReport{}, err
	}
	if err := decoder.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return DNSWarmReport{}, errors.New("trailing data in DNS report")
	}
	age := now.Sub(wire.ObservedAt)
	if wire.ObservedAt.IsZero() || age < 0 || age > 15*time.Second || wire.PolicyRevision == nil || *wire.PolicyRevision < 0 || wire.Automatic == nil || len(wire.Automatic) > MaxReportNames {
		return DNSWarmReport{}, errors.New("incomplete or expired DNS report")
	}
	seen := make(map[string]bool, len(wire.Automatic))
	for _, row := range wire.Automatic {
		if !IsCanonicalDomain(row.Domain) || row.ClientRequests < 1 || seen[row.Domain] {
			return DNSWarmReport{}, errors.New("invalid automatic DNS membership entry")
		}
		seen[row.Domain] = true
	}
	return DNSWarmReport{ObservedAt: wire.ObservedAt, PolicyRevision: *wire.PolicyRevision, Automatic: wire.Automatic}, nil
}
