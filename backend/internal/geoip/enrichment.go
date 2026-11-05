package geoip

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"maps"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/Artik-Man/Hestia/internal/netaddress"
)

const (
	cacheLife  = 7 * 24 * time.Hour
	cacheLimit = 4096
	queueLimit = 256
)

// ErrToken indicates an oversized key or one containing whitespace or control characters.
var ErrToken = errors.New("invalid 2ip token")

// cachedCountry expires an exact IP independently of changes to the baseline country database.
type cachedCountry struct {
	Country string    `json:"country"`
	Expires time.Time `json:"expires"`
}

// Enrichment coordinates one background provider and the exact-IP overrides consumed by both clients.
type Enrichment struct {
	mu                             sync.RWMutex
	tokenPath, cachePath, rulesDir string
	token                          string
	generation                     uint64
	cache                          map[netip.Addr]cachedCountry
	pending, attempted             map[netip.Addr]time.Time
	dirty                          bool
	published                      map[string][]string
	client                         *http.Client
	endpoint                       string
}

// NewEnrichment restores private credentials and recent valid observations, then reconciles public rule sets.
func NewEnrichment(privateDir, rulesDir string) (*Enrichment, error) {
	s := &Enrichment{
		tokenPath: filepath.Join(privateDir, "2ip.key"),
		cachePath: filepath.Join(privateDir, "2ip-cache.json"),
		rulesDir:  rulesDir,
		cache:     make(map[netip.Addr]cachedCountry),
		pending:   make(map[netip.Addr]time.Time),
		attempted: make(map[netip.Addr]time.Time),
		published: make(map[string][]string),
		client:    &http.Client{Timeout: 5 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }},
		endpoint:  "https://api.2ip.io/",
	}
	token, err := os.ReadFile(s.tokenPath)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	s.token = string(token)
	if !validToken(s.token) {
		return nil, ErrToken
	}
	if err := s.restore(); err != nil {
		return nil, err
	}
	if rulesDir != "" {
		if err := os.MkdirAll(rulesDir, 0750); err != nil {
			return nil, err
		}
		if err := s.publish(s.cache); err != nil {
			return nil, err
		}
	}
	return s, nil
}

// validToken accepts an empty key to disable requests and visible ASCII for the provider credential.
func validToken(token string) bool {
	if len(token) > 256 {
		return false
	}
	for _, char := range token {
		if char < '!' || char > '~' {
			return false
		}
	}
	return true
}

// Configured reports whether the service can query 2ip without disclosing its token.
func (s *Enrichment) Configured() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.token != ""
}

// SetToken saves a new private key atomically and discards work queued for the old credential.
func (s *Enrichment) SetToken(token string) error {
	token = strings.TrimSpace(token)
	if !validToken(token) {
		return ErrToken
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := replace(s.tokenPath, []byte(token), 0600); err != nil {
		return err
	}
	s.token = token
	s.generation++
	clear(s.pending)
	clear(s.attempted)
	return nil
}

// Country returns an unexpired exact-IP correction or an empty string to use the baseline.
func (s *Enrichment) Country(address string) string {
	if s == nil {
		return ""
	}
	addr, err := netip.ParseAddr(address)
	if err != nil {
		return ""
	}
	s.mu.RLock()
	defer s.mu.RUnlock()
	entry := s.cache[addr.Unmap()]
	if entry.Expires.After(time.Now()) {
		return entry.Country
	}
	return ""
}

// Observe queues a newly recorded public numeric destination once, without blocking capture on network I/O.
func (s *Enrichment) Observe(address string) {
	if s == nil {
		return
	}
	ip, err := netip.ParseAddr(address)
	if err != nil {
		return
	}
	ip = ip.Unmap()
	if !netaddress.Public(ip) {
		return
	}
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.token == "" || s.cache[ip].Expires.After(now) || s.attempted[ip].After(now) || len(s.pending) >= queueLimit {
		return
	}
	s.pending[ip] = now.Add(5 * time.Minute)
}

// next takes one current destination and remembers the attempt, including rejected provider lookups.
func (s *Enrichment) next(now time.Time) (netip.Addr, string, uint64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for ip, expires := range s.pending {
		delete(s.pending, ip)
		if expires.After(now) && s.token != "" {
			s.attempted[ip] = now.Add(15 * time.Minute)
			return ip, s.token, s.generation
		}
	}
	return netip.Addr{}, "", 0
}

// lookup submits only the numeric destination to 2ip; failures cannot publish a result or leak its URL in logs.
func (s *Enrichment) lookup(ctx context.Context, ip netip.Addr, token string) (string, bool) {
	target := s.endpoint + ip.String() + "?" + url.Values{"token": {token}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return "", false
	}
	res, err := s.client.Do(req)
	if err != nil {
		return "", false
	}
	defer res.Body.Close()
	if res.StatusCode != http.StatusOK {
		return "", res.StatusCode == http.StatusTooManyRequests
	}
	const maxBody = 16 << 10
	data, err := io.ReadAll(io.LimitReader(res.Body, maxBody+1))
	var result struct {
		IP   netip.Addr `json:"ip"`
		Code string     `json:"code"`
	}
	if err != nil || len(data) > maxBody || json.Unmarshal(data, &result) != nil || result.IP.Unmap() != ip || !supported(result.Code) {
		return "", false
	}
	return result.Code, false
}

// supported accepts exactly an assigned two-letter ISO country in the shared catalogue.
func supported(code string) bool {
	return len(code) == 2 && slices.Contains(strings.Fields(CountryCodes), code)
}

// remember installs a successful observation only if its credential still applies; it bounds cache memory.
func (s *Enrichment) remember(ip netip.Addr, code string, generation uint64, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if generation != s.generation || s.token == "" {
		return
	}
	if len(s.cache) >= cacheLimit {
		var oldest netip.Addr
		for key, entry := range s.cache {
			if !oldest.IsValid() || entry.Expires.Before(s.cache[oldest].Expires) {
				oldest = key
			}
		}
		delete(s.cache, oldest)
	}
	s.cache[ip] = cachedCountry{code, now.Add(cacheLife)}
	s.dirty = true
}

// Run processes at most one unique IP per second, maintaining the offline fallback across service failures.
func (s *Enrichment) Run(ctx context.Context) {
	tick := time.NewTimer(time.Second)
	defer tick.Stop()
	var retry time.Time
	nextFlush := time.Now().Add(time.Minute)
	defer func() { s.flush(time.Now()) }()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-tick.C:
			if !now.Before(nextFlush) {
				s.flush(now)
				nextFlush = now.Add(time.Minute)
			}
			if !now.Before(retry) {
				ip, token, generation := s.next(now)
				if ip.IsValid() {
					code, quota := s.lookup(ctx, ip, token)
					if quota {
						retry = time.Now().Add(time.Minute)
					}
					if code != "" {
						s.remember(ip, code, generation, time.Now())
					}
				}
			}
			tick.Reset(time.Second)
		}
	}
}

// flush removes expired results and retries durable state and rule publication following storage errors.
func (s *Enrichment) flush(now time.Time) {
	s.mu.Lock()
	for ip, entry := range s.cache {
		if !entry.Expires.After(now) {
			delete(s.cache, ip)
			s.dirty = true
		}
	}
	for ip, until := range s.attempted {
		if !until.After(now) {
			delete(s.attempted, ip)
		}
	}
	if !s.dirty {
		s.mu.Unlock()
		return
	}
	// Run is the sole cache writer; the HTTP and capture paths only read it.
	snapshot := maps.Clone(s.cache)
	s.mu.Unlock()
	data, err := json.Marshal(snapshot)
	if err == nil {
		err = replace(s.cachePath, data, 0600)
	}
	if err == nil && s.rulesDir != "" {
		err = s.publish(snapshot)
	}
	if err != nil {
		log.Print("GeoIP: cannot persist country corrections")
		return
	}
	s.mu.Lock()
	s.dirty = false
	s.mu.Unlock()
}

// restore rejects malformed persisted data before it can become a routing input.
func (s *Enrichment) restore() error {
	f, err := os.Open(s.cachePath)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, 1<<20))
	if err != nil {
		return err
	}
	var entries map[netip.Addr]cachedCountry
	if len(data) >= 1<<20 || json.Unmarshal(data, &entries) != nil || len(entries) > cacheLimit {
		return errors.New("invalid GeoIP cache")
	}
	now := time.Now()
	for ip, entry := range entries {
		if ip != ip.Unmap() || !netaddress.Public(ip) || !supported(entry.Country) {
			return errors.New("invalid GeoIP cache entry")
		}
		if entry.Expires.After(now) && !entry.Expires.After(now.Add(cacheLife)) {
			s.cache[ip] = entry
		}
	}
	return nil
}

// publish updates only changed country rule sets. Each atomic replacement can reload independently in sing-box.
func (s *Enrichment) publish(cache map[netip.Addr]cachedCountry) error {
	sets := make(map[string][]string)
	for ip, entry := range cache {
		sets[entry.Country] = append(sets[entry.Country], netip.PrefixFrom(ip, ip.BitLen()).String())
	}
	for _, code := range strings.Fields(CountryCodes) {
		cidrs := sets[code]
		slices.Sort(cidrs)
		if previous, ok := s.published[code]; ok && slices.Equal(previous, cidrs) {
			continue
		}
		type rule struct {
			CIDRs []string `json:"ip_cidr"`
		}
		rules := []rule{}
		if len(cidrs) > 0 {
			rules = append(rules, rule{cidrs})
		}
		data, err := json.Marshal(struct {
			Version int    `json:"version"`
			Rules   []rule `json:"rules"`
		}{3, rules})
		if err != nil {
			return err
		}
		path := filepath.Join(s.rulesDir, code+".json")
		// On startup keep unchanged files in place so sing-box does not reload every country.
		existing, readErr := os.ReadFile(path)
		if readErr != nil || !bytes.Equal(existing, data) {
			if err = replace(path, data, 0640); err != nil {
				return err
			}
		}
		s.published[code] = cidrs
	}
	return nil
}

// replace syncs a complete file under the required mode before atomically publishing it in its directory.
func replace(path string, data []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	f, err := os.CreateTemp(dir, ".geoip-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err == nil {
		err = os.Rename(f.Name(), path)
	}
	if err != nil {
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
