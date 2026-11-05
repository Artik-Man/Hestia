package binding

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/Artik-Man/Hestia/internal/controller"
	"github.com/Artik-Man/Hestia/internal/panelmodel"
)

// ISO 3166-1 alpha-2 country and territory codes (IANA tzdata iso3166.tab).
var countryCodes = strings.Fields("AD AE AF AG AI AL AM AO AQ AR AS AT AU AW AX AZ BA BB BD BE BF BG BH BI BJ BL BM BN BO BQ BR BS BT BV BW BY BZ CA CC CD CF CG CH CI CK CL CM CN CO CR CU CV CW CX CY CZ DE DJ DK DM DO DZ EC EE EG EH ER ES ET FI FJ FK FM FO FR GA GB GD GE GF GG GH GI GL GM GN GP GQ GR GS GT GU GW GY HK HM HN HR HT HU ID IE IL IM IN IO IQ IR IS IT JE JM JO JP KE KG KH KI KM KN KP KR KW KY KZ LA LB LC LI LK LR LS LT LU LV LY MA MC MD ME MF MG MH MK ML MM MN MO MP MQ MR MS MT MU MV MW MX MY MZ NA NC NE NF NG NI NL NO NP NR NU NZ OM PA PE PF PG PH PK PL PM PN PR PS PT PW PY QA RE RO RS RU RW SA SB SC SD SE SG SH SI SJ SK SL SM SN SO SR SS ST SV SX SY SZ TC TD TF TG TH TJ TK TL TM TN TO TR TT TV TW TZ UA UG UM US UY UZ VA VC VE VG VI VN VU WF WS YE YT ZA ZM ZW")
var ErrInvalidCountryMap = errors.New("invalid country assignments")

// CountryMap reads or replaces the installed policy while holding the same lock as topology changes.
// First access captures the current default once. A pending transaction prevents any access.
func (e Engine) CountryMap(change *panelmodel.CountryMap) (panelmodel.CountryMap, error) {
	lock, err := e.acquire(false)
	if err != nil {
		return panelmodel.CountryMap{}, err
	}
	defer lock.Close()
	if _, err := os.Lstat(filepath.Join(e.dir, pending)); !errors.Is(err, os.ErrNotExist) {
		return panelmodel.CountryMap{}, ErrUnavailable
	}
	return e.lockCountryMap(filepath.Join(e.dir, "snapshot.json"), change)
}

// CustomCountryMap opens an explicitly configured policy for a standalone panel with an unmanaged snapshot.
func CustomCountryMap(snapshot, path string) func(*panelmodel.CountryMap) (panelmodel.CountryMap, error) {
	e := Engine{countryMapPath: path}
	return func(change *panelmodel.CountryMap) (panelmodel.CountryMap, error) {
		return e.lockCountryMap(snapshot, change)
	}
}

// lockCountryMap serializes initialization and writes across panel processes without excluding other inventory readers.
func (e Engine) lockCountryMap(snapshot string, change *panelmodel.CountryMap) (panelmodel.CountryMap, error) {
	lock, err := os.OpenFile(e.countryMapPath+".lock", os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return panelmodel.CountryMap{}, err
	}
	defer lock.Close()
	if err = syscall.Flock(int(lock.Fd()), syscall.LOCK_EX); err != nil {
		return panelmodel.CountryMap{}, err
	}
	return e.accessCountryMap(snapshot, change)
}

// accessCountryMap resolves the inventory under the caller's lock and publishes only validated complete changes.
func (e Engine) accessCountryMap(snapshot string, change *panelmodel.CountryMap) (panelmodel.CountryMap, error) {
	var empty panelmodel.CountryMap
	data, err := os.ReadFile(snapshot)
	if err != nil {
		return empty, err
	}
	cfg, err := controller.CheckSnapshot(data)
	if err != nil || len(cfg.Groups) == 0 {
		return empty, ErrUnavailable
	}
	current, err := e.readCountryMap()
	if errors.Is(err, os.ErrNotExist) {
		if change != nil {
			return empty, ErrConflict
		}
		current.Assignments = make(map[string]string, len(countryCodes))
		for _, code := range countryCodes {
			current.Assignments[code] = cfg.Groups[0].ID
		}
		return e.saveCountryMap(current)
	}
	if err != nil {
		return empty, err
	}
	if change == nil {
		return current, nil
	}
	if change.Version != current.Version {
		return empty, ErrConflict
	}
	available := make(map[string]bool, len(cfg.Groups))
	for _, g := range cfg.Groups {
		available[g.ID] = true
	}
	if !completeCountryMap(*change) {
		return empty, ErrInvalidCountryMap
	}
	for _, group := range change.Assignments {
		if !available[group] {
			return empty, ErrInvalidCountryMap
		}
	}
	if change.Enabled == current.Enabled && maps.Equal(change.Assignments, current.Assignments) {
		return current, nil
	}
	return e.saveCountryMap(*change)
}

// completeCountryMap requires each supported country exactly once with a nonempty routing ID.
func completeCountryMap(policy panelmodel.CountryMap) bool {
	if len(policy.Assignments) != len(countryCodes) || policy.Version == "" {
		return false
	}
	for _, code := range countryCodes {
		if policy.Assignments[code] == "" {
			return false
		}
	}
	return true
}

// readCountryMap reads only a bounded regular policy file, rejecting corruption before writes or group deletion.
func (e Engine) readCountryMap() (panelmodel.CountryMap, error) {
	var policy panelmodel.CountryMap
	f, err := os.OpenFile(e.countryMapPath, os.O_RDONLY|syscall.O_NONBLOCK|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return policy, err
	}
	defer f.Close()
	const maxSize = 128 << 10
	if info, err := f.Stat(); err != nil || !info.Mode().IsRegular() || info.Size() > maxSize {
		return policy, ErrUnavailable
	}
	data, err := io.ReadAll(io.LimitReader(f, maxSize+1))
	if err != nil {
		return policy, err
	}
	var fields struct {
		Enabled *bool `json:"enabled"`
	}
	if len(data) > maxSize || json.Unmarshal(data, &policy) != nil || json.Unmarshal(data, &fields) != nil || fields.Enabled == nil || !completeCountryMap(policy) {
		return policy, ErrUnavailable
	}
	return policy, nil
}

// saveCountryMap replaces the durable file with a fresh version after flushing all assignments to disk.
func (e Engine) saveCountryMap(policy panelmodel.CountryMap) (panelmodel.CountryMap, error) {
	policy.Version = rand.Text()
	dir := filepath.Dir(e.countryMapPath)
	f, err := os.CreateTemp(dir, ".country-map-")
	if err != nil {
		return panelmodel.CountryMap{}, err
	}
	defer os.Remove(f.Name())
	// The installed state directory is setgid root. Only the panel and the root
	// deletion helper may read its policy; the helper has no DAC bypass capability.
	if e.lock != "" {
		err = f.Chmod(0640)
	}
	if err == nil {
		err = json.NewEncoder(f).Encode(policy)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(f.Name(), e.countryMapPath)
	}
	if err == nil {
		err = syncDir(dir)
	}
	return policy, err
}

// checkCountryReferences prevents deleting any group referenced by the saved policy, including when disabled.
func (e Engine) checkCountryReferences(id string) error {
	if e.countryMapPath == "" {
		return nil
	}
	current, err := e.readCountryMap()
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return ErrUnavailable
	}
	for _, assigned := range current.Assignments {
		if assigned == id {
			return ErrConflict
		}
	}
	return nil
}
