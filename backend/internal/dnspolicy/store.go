package dnspolicy

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"syscall"
)

// DNSSettings defines persisted DNS policy in the units used by the panel.
type DNSSettings struct {
	RetentionSeconds   int  `json:"retentionSeconds" minimum:"0" maximum:"31536000"`
	ServeStale         bool `json:"serveStale"`
	StaleWindowSeconds int  `json:"staleWindowSeconds" minimum:"0" maximum:"31536000"`
	AutomaticEnabled   bool `json:"automaticEnabled"`
	Threshold          int  `json:"threshold" minimum:"1" maximum:"1000000"`
	WindowHours        int  `json:"windowHours" minimum:"1" maximum:"8760"`
	IntervalMinutes    int  `json:"intervalMinutes" minimum:"1" maximum:"525600"`
}

// Policy stores independently editable manual pins and automatic exclusions alongside settings.
type Policy struct {
	Settings   DNSSettings `json:"settings"`
	Manual     []string    `json:"manual" maxItems:"4096" nullable:"false"`
	Exclusions []string    `json:"exclusions" maxItems:"4096" nullable:"false"`
}

// Snapshot identifies one durable policy version; absent files use revision zero.
type Snapshot struct {
	Revision int    `json:"revision" minimum:"0"`
	Policy   Policy `json:"policy"`
}

// Store persists a single policy at Path; concurrent writers synchronize across processes.
type Store struct{ Path string }

var (
	ErrConflict = errors.New("версия настроек DNS изменилась")
	ErrInvalid  = errors.New("недопустимая политика DNS")
)

// Read returns complete durable state or defaults on first installation; corrupt files fail closed.
func (s Store) Read() (Snapshot, error) {
	file, err := os.OpenFile(s.Path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
	if errors.Is(err, os.ErrNotExist) {
		return Snapshot{Policy: Policy{Settings: DNSSettings{AutomaticEnabled: true, Threshold: 5, WindowHours: 24, IntervalMinutes: 10}, Manual: []string{}, Exclusions: []string{}}}, nil
	}
	if err != nil {
		return Snapshot{}, err
	}
	defer file.Close()
	const limit = 3 << 20
	info, err := file.Stat()
	if err != nil {
		return Snapshot{}, err
	}
	if !info.Mode().IsRegular() || info.Size() > limit {
		return Snapshot{}, errors.New("недопустимый файл настроек DNS")
	}
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return Snapshot{}, err
	}
	if len(data) > limit {
		return Snapshot{}, errors.New("слишком большой файл настроек DNS")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var snap Snapshot
	if err := decoder.Decode(&snap); err != nil {
		return Snapshot{}, err
	}
	if err := decoder.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return Snapshot{}, errors.New("лишние данные в файле настроек DNS")
	}
	// encoding/json treats null scalar fields as zero; required zero-valued flags must be present.
	var fields struct {
		Policy struct {
			Settings map[string]json.RawMessage `json:"settings"`
		} `json:"policy"`
	}
	if err := json.Unmarshal(data, &fields); err != nil {
		return Snapshot{}, err
	}
	for _, name := range []string{"retentionSeconds", "serveStale", "staleWindowSeconds", "automaticEnabled", "threshold", "windowHours", "intervalMinutes"} {
		field := fields.Policy.Settings[name]
		if len(field) == 0 || bytes.Equal(field, []byte("null")) {
			return Snapshot{}, errors.New("неполный файл настроек DNS")
		}
	}
	canonical, err := snap.Policy.normalized()
	if err != nil || snap.Revision < 1 || !reflect.DeepEqual(canonical, snap.Policy) {
		return Snapshot{}, errors.New("повреждён файл настроек DNS")
	}
	return snap, nil
}

// Apply atomically compares the current revision and stores the canonical policy. Equivalent
// updates keep their revision. Failed validation and revision conflicts leave the file unchanged.
func (s Store) Apply(expectedRevision int, policy Policy) (Snapshot, error) {
	if expectedRevision < 0 {
		return Snapshot{}, fmt.Errorf("%w: отрицательная версия", ErrInvalid)
	}
	canonical, err := policy.normalized()
	if err != nil {
		return Snapshot{}, err
	}
	dir := filepath.Dir(s.Path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return Snapshot{}, err
	}
	lock, err := os.OpenFile(s.Path+".lock", os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return Snapshot{}, err
	}
	defer lock.Close()
	if err := syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return Snapshot{}, err
	}
	current, err := s.Read()
	if err != nil {
		return Snapshot{}, err
	}
	if current.Revision != expectedRevision {
		return Snapshot{}, ErrConflict
	}
	if current.Revision > 0 && reflect.DeepEqual(current.Policy, canonical) {
		return current, nil
	}
	if current.Revision >= math.MaxInt32 {
		return Snapshot{}, errors.New("исчерпан диапазон версий настроек DNS")
	}
	next := Snapshot{Revision: current.Revision + 1, Policy: canonical}
	if err := s.write(next); err != nil {
		return Snapshot{}, err
	}
	return s.Read()
}

// write replaces the settings file after syncing a complete temporary copy and syncs the directory entry.
func (s Store) write(snapshot Snapshot) error {
	dir, err := os.Open(filepath.Dir(s.Path))
	if err != nil {
		return err
	}
	defer dir.Close()
	f, err := os.CreateTemp(dir.Name(), ".dns-policy-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(0640); err == nil {
		err = json.NewEncoder(f).Encode(snapshot)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	if err := os.Rename(f.Name(), s.Path); err != nil {
		return err
	}
	return dir.Sync()
}

// normalized validates numeric bounds and canonicalizes both independent lists without mutating the input.
func (p Policy) normalized() (Policy, error) {
	s := p.Settings
	if s.RetentionSeconds < 0 || s.RetentionSeconds > 31536000 || s.StaleWindowSeconds < 0 || s.StaleWindowSeconds > 31536000 ||
		s.Threshold < 1 || s.Threshold > 1000000 || s.WindowHours < 1 || s.WindowHours > 8760 || s.IntervalMinutes < 1 || s.IntervalMinutes > 525600 {
		return Policy{}, fmt.Errorf("%w: проверьте диапазоны параметров хранения и прогрева", ErrInvalid)
	}
	if s.ServeStale && (s.StaleWindowSeconds == 0 || s.StaleWindowSeconds > s.RetentionSeconds) {
		return Policy{}, fmt.Errorf("%w: аварийное окно должно быть положительным и укладываться в срок хранения", ErrInvalid)
	}
	var err error
	p.Manual, err = normalizeNames(p.Manual)
	if err != nil {
		return Policy{}, err
	}
	p.Exclusions, err = normalizeNames(p.Exclusions)
	return p, err
}

// normalizeNames returns a sorted copy and rejects duplicates after exact-domain normalization.
func normalizeNames(input []string) ([]string, error) {
	if input == nil || len(input) > 4096 {
		return nil, fmt.Errorf("%w: укажите список до 4096 доменов", ErrInvalid)
	}
	names := make([]string, 0, len(input))
	for _, raw := range input {
		name := strings.TrimSuffix(raw, ".")
		if !validDomain(name) {
			return nil, fmt.Errorf("%w: требуется точное DNS-имя в ASCII или Punycode", ErrInvalid)
		}
		names = append(names, strings.ToLower(name))
	}
	slices.Sort(names)
	for i := 1; i < len(names); i++ {
		if names[i-1] == names[i] {
			return nil, fmt.Errorf("%w: домен уже в списке", ErrInvalid)
		}
	}
	return names, nil
}

// IsCanonicalDomain verifies that a measured name can be represented in policy and report snapshots.
func IsCanonicalDomain(name string) bool {
	return validDomain(name) && name == strings.ToLower(name)
}

// validDomain accepts DNS host labels, including single-label names, and rejects address literals.
func validDomain(name string) bool {
	if len(name) == 0 || len(name) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(name); err == nil {
		return false
	}
	for label := range strings.SplitSeq(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-') {
				return false
			}
		}
	}
	return true
}
