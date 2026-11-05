package quality

import (
	"context"
	"reflect"
	"slices"
	"strconv"
	"sync"
	"time"
)

// TargetResult retains the evidence for one target in the selected window.
type TargetResult struct {
	Target           string         `json:"target"`
	Samples          int            `json:"samples"`
	Successes        int            `json:"successes"`
	LocalErrors      int            `json:"localErrors"`
	DNSErrors        int            `json:"dnsErrors"`
	DNSResponseCodes map[string]int `json:"dnsResponseCodes,omitempty" doc:"Число полученных ответов с ненулевым кодом DNS, ключ — десятичный RCODE."`
	Score            *float64       `json:"score" nullable:"true"`
}

// CheckResult counts all completed exchanges in one transport check.
type CheckResult struct {
	Protocol    string         `json:"protocol" enum:"UDP,TCP,ICMP,DNS,HTTPS,HTTP3"`
	Samples     int            `json:"samples"`
	Successes   int            `json:"successes"`
	LocalErrors int            `json:"localErrors"`
	Score       *float64       `json:"score" nullable:"true"`
	Targets     []TargetResult `json:"targets" nullable:"false"`
}

// Result contains a connection's check scores and their arithmetic mean when all are known.
type Result struct {
	Checks  []CheckResult `json:"checks" nullable:"false"`
	Overall *float64      `json:"overall" nullable:"true"`
}

type seriesKey struct{ id, protocol, target string }
type sample struct {
	time    time.Time
	outcome outcome
}
type observation struct {
	key    seriesKey
	sample sample
}

// Engine schedules comparable probes and owns independently timestamped observations for the running worker session.
type Engine struct {
	mu       sync.RWMutex
	settings Settings
	epochs   map[string]uint64
	started  time.Time
	history  map[seriesKey]*windowSeries
}

// NewEngine loads persisted settings and creates empty measurement history.
func NewEngine(path string) (*Engine, error) {
	s, err := LoadSettings(path)
	if err != nil {
		return nil, err
	}
	return &Engine{settings: s, epochs: map[string]uint64{}, started: time.Now(), history: map[seriesKey]*windowSeries{}}, nil
}

// cloneSettings returns a deep copy so readers cannot mutate worker state.
func cloneSettings(s Settings) Settings {
	s.Checks = slices.Clone(s.Checks)
	for i := range s.Checks {
		s.Checks[i].Targets = slices.Clone(s.Checks[i].Targets)
	}
	return s
}

// Settings returns a point-in-time copy of the current configuration.
func (e *Engine) Settings() Settings {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return cloneSettings(e.settings)
}

// ApplySettings adopts settings loaded from the authoritative file without rewriting it.
func (e *Engine) ApplySettings(s Settings) error {
	if err := s.Validate(); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	e.apply(s)
	return nil
}

// apply discards obsolete observations and invalidates in-flight rounds whenever a check changes.
func (e *Engine) apply(s Settings) {
	if reflect.DeepEqual(e.settings, s) {
		return
	}
	for _, old := range e.settings.Checks {
		if slices.ContainsFunc(s.Checks, func(c Check) bool { return reflect.DeepEqual(c, old) }) {
			continue
		}
		e.epochs[old.Protocol]++
		for key := range e.history {
			if key.protocol == old.Protocol {
				delete(e.history, key)
			}
		}
	}
	e.settings = cloneSettings(s)
}

// Snapshot evaluates all requested connections with the same window, settings and set of completed rounds.
func (e *Engine) Snapshot(ids []string) (Settings, map[string]Result) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.expire(time.Now())
	results := make(map[string]Result, len(ids))
	for _, id := range ids {
		results[id] = e.scores(id)
	}
	return cloneSettings(e.settings), results
}

// scores excludes local failures and weights each configured check equally, including a genuine zero score.
func (e *Engine) scores(id string) Result {
	r := Result{Checks: []CheckResult{}}
	sum := 0.
	complete := len(e.settings.Checks) > 0
	for _, c := range e.settings.Checks {
		check := CheckResult{Protocol: c.Protocol, Targets: []TargetResult{}}
		for _, target := range c.Targets {
			v := TargetResult{Target: target}
			if s := e.history[seriesKey{id, c.Protocol, target}]; s != nil {
				v.LocalErrors = s.counts[localError]
				for index, count := range s.counts[dnsError:] {
					if count == 0 {
						continue
					}
					if v.DNSResponseCodes == nil {
						v.DNSResponseCodes = map[string]int{}
					}
					v.DNSResponseCodes[strconv.Itoa(index+1)] = count
					v.DNSErrors += count
				}
				v.Samples = s.counts[success] + s.counts[failure] + v.DNSErrors
				v.Successes = s.counts[success]
				if c.Protocol == UDP {
					v.Successes += v.DNSErrors
				}
			}
			v.Score = score(v.Successes, v.Samples)
			check.Samples += v.Samples
			check.Successes += v.Successes
			check.LocalErrors += v.LocalErrors
			check.Targets = append(check.Targets, v)
		}
		check.Score = score(check.Successes, check.Samples)
		if check.Score == nil {
			complete = false
		} else {
			sum += *check.Score
		}
		r.Checks = append(r.Checks, check)
	}
	if complete {
		v := sum / float64(len(r.Checks))
		r.Overall = &v
	}
	return r
}

// score returns the exact success percentage or nil for an empty denominator.
func score(successes, samples int) *float64 {
	if samples == 0 {
		return nil
	}
	n := 100 * float64(successes) / float64(samples)
	return &n
}

// Run schedules each protocol independently and waits for all workers at shutdown. Topology must include reserve paths.
func (e *Engine) Run(ctx context.Context, paths func(context.Context) ([]Path, error)) {
	var workers sync.WaitGroup
	for _, protocol := range protocols {
		workers.Add(1)
		go func() { defer workers.Done(); e.runCheck(ctx, protocol, paths) }()
	}
	workers.Wait()
}

// runCheck picks up schedule changes within a second and never overlaps rounds of the same protocol.
func (e *Engine) runCheck(ctx context.Context, protocol string, paths func(context.Context) ([]Path, error)) {
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	var next time.Time
	var lastEpoch uint64
	for ctx.Err() == nil {
		e.mu.RLock()
		epoch := e.epochs[protocol]
		var current Check
		for _, c := range e.settings.Checks {
			if c.Protocol == protocol {
				current = c
				break
			}
		}
		e.mu.RUnlock()
		now := time.Now()
		if current.Protocol != "" && (epoch != lastEpoch || !now.Before(next)) {
			lastEpoch = epoch
			if pp, err := paths(ctx); err == nil {
				e.round(ctx, pp, current, epoch)
				next = now.Add(time.Duration(current.IntervalSeconds) * time.Second)
			}
		}
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// round measures all targets through each independent path with bounded concurrency and publishes the round together.
func (e *Engine) round(ctx context.Context, paths []Path, c Check, epoch uint64) {
	var wg sync.WaitGroup
	obs := make([]observation, len(paths)*len(c.Targets))
	slots := make(chan struct{}, 24)
	for i, p := range paths {
		for j, target := range c.Targets {
			select {
			case slots <- struct{}{}:
			case <-ctx.Done():
				wg.Wait()
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				defer func() { <-slots }()
				result := probe(ctx, p, c, target)
				obs[i*len(c.Targets)+j] = observation{seriesKey{p.ID, c.Protocol, target}, sample{time.Now(), result}}
			}()
		}
	}
	wg.Wait()
	if ctx.Err() != nil {
		return
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.epochs[c.Protocol] != epoch {
		return
	}
	for _, item := range obs {
		e.record(item.key, item.sample.time, item.sample.outcome)
	}
	e.expire(time.Now())
}
