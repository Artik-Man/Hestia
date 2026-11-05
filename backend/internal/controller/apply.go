package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"slices"
	"strings"
	"time"

	"github.com/Artik-Man/Hestia/internal/routing"
)

const localAPI = "http://127.0.0.1:9090"

type Result struct {
	Time           time.Time           `json:"time"`
	Domain         string              `json:"domain"`
	Group          string              `json:"group"`
	Exit           string              `json:"exit,omitempty"`
	List           string              `json:"list,omitempty"`
	Mask           string              `json:"mask,omitempty"`
	Reason         routing.MatchReason `json:"reason"`
	Outcome        routing.Outcome     `json:"outcome"`
	SelectorTarget string              `json:"selector_target"`
}

type selector struct {
	Type string   `json:"type"`
	Now  string   `json:"now"`
	All  []string `json:"all"`
}

// Apply updates the selected group's preconfigured selector under a single writer.
func Apply(ctx context.Context, cfg Config, domain string) (Result, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	client := newClient()
	defer client.CloseIdleConnections()
	return apply(ctx, client, localAPI, cfg, domain)
}

// newClient creates a direct HTTP client for the local API with proxying and
// redirects disabled so selector requests stay at the configured endpoint.
func newClient() *http.Client {
	return &http.Client{
		Transport:     &http.Transport{Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// apply validates the candidate, selects the group for domain, and reconciles
// its selector. An unavailable group requests the reserved deny target.
func apply(ctx context.Context, client *http.Client, base string, cfg Config, domain string) (Result, error) {
	if err := cfg.validate(); err != nil {
		return Result{}, err
	}
	d := routing.Decide(cfg.Groups, cfg.Lists, cfg.Healthy, domain)
	target := d.Exit
	switch d.Outcome {
	case routing.Block:
		target = deny
	case routing.Forward:
	default:
		return Result{}, fmt.Errorf("rejected decision: %s", d.Reason)
	}
	for _, group := range cfg.Groups {
		if group.ID == d.Group {
			_, err := ownedReconcile(ctx, client, base, group, target)
			if err != nil {
				return Result{}, err
			}
			break
		}
	}
	return Result{Time: time.Now().UTC(), Domain: domain, Group: d.Group, Exit: d.Exit, List: d.List, Mask: d.Mask, Reason: d.Reason, Outcome: d.Outcome, SelectorTarget: target}, nil
}

// reconcile checks the effective selector, writes only on divergence and confirms the write.
func reconcile(ctx context.Context, client *http.Client, base string, group routing.Group, target string) (bool, error) {
	return reconcileDecision(ctx, client, base, group, func(string) string { return target })
}

// reconcileDecision derives the desired target from verified live membership and confirms any selector change.
func reconcileDecision(ctx context.Context, client *http.Client, base string, group routing.Group, choose func(string) string) (bool, error) {
	endpoint := base + "/proxies/" + url.PathEscape(group.ID)
	members := append([]string{deny}, group.Exits...)
	current, err := readSelector(ctx, client, endpoint)
	if err != nil {
		return false, fmt.Errorf("selector preflight: %w", err)
	}
	if !current.matches(members) {
		return false, fmt.Errorf("selector %q membership or type differs from configuration", group.ID)
	}
	target := choose(current.Now)
	if current.Now != target {
		if err := setTarget(ctx, client, endpoint, target); err != nil {
			return false, fmt.Errorf("selector update not confirmed: %w", err)
		}
		actual, err := readSelector(ctx, client, endpoint)
		if err != nil {
			return false, fmt.Errorf("selector update not confirmed: %w", err)
		}
		if actual.Now != target || !actual.matches(members) {
			return false, fmt.Errorf("selector update not confirmed: expected %q, observed %q", target, actual.Now)
		}
		return true, nil
	}
	return false, nil
}

// matches checks that sing-box reports a selector with exactly the configured
// members and that its current target belongs to that set.
func (s selector) matches(members []string) bool {
	if s.Type != "Selector" || len(s.All) != len(members) || !slices.Contains(s.All, s.Now) {
		return false
	}
	for _, m := range members {
		if !slices.Contains(s.All, m) {
			return false
		}
	}
	return true
}

// readSelector retrieves the current target and membership reported by the API.
// Callers validate the returned state against their configuration.
func readSelector(ctx context.Context, client *http.Client, endpoint string) (selector, error) {
	var state selector
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return state, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return state, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return state, fmt.Errorf("GET selector: %s", resp.Status)
	}
	err = json.NewDecoder(resp.Body).Decode(&state)
	return state, err
}

// setTarget sends a selector update and checks for the expected acknowledgement.
// The caller must read back the target to confirm the change.
func setTarget(ctx context.Context, client *http.Client, endpoint, target string) error {
	body, err := json.Marshal(struct {
		Name string `json:"name"`
	}{Name: target})
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusNoContent {
		return fmt.Errorf("PUT selector: %s", resp.Status)
	}
	return nil
}

// DNSExits reads the selected live exit of each applicable group without mutating selectors.
// An explicit rule permits only its group; a failed selector or unhealthy exit provides no path.
func DNSExits(ctx context.Context, cfg Config, domain string) ([]string, error) {
	client := newClient()
	defer client.CloseIdleConnections()
	return dnsExits(ctx, client, localAPI, cfg, domain)
}

var serviceOwnerLabel = regexp.MustCompile(`^_?[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?$`)

// dnsRoutingName returns the longest hostname suffix usable by domain masks. It preserves
// normal names for the routing parser and treats only the DNS root as an empty name.
// Service labels may drop earlier labels only when the complete wire owner is unambiguous.
func dnsRoutingName(domain string) (string, error) {
	if domain == "." {
		return "", nil
	}
	if !strings.Contains(domain, "_") {
		return domain, nil
	}
	name := strings.TrimSuffix(domain, ".")
	if len(name) > 253 {
		return "", fmt.Errorf("DNS owner is too long")
	}
	position, suffixStart := 0, 0
	for label := range strings.SplitSeq(name, ".") {
		if len(label) > 63 || !serviceOwnerLabel.MatchString(label) {
			return "", fmt.Errorf("invalid service DNS label")
		}
		position += len(label) + 1
		if label[0] == '_' {
			// No domain mask can contain an underscore, so a match may only begin after this label.
			suffixStart = position
		}
	}
	if suffixStart >= len(name) {
		return "", fmt.Errorf("DNS service owner has no hostname suffix")
	}
	return name[suffixStart:], nil
}

// dnsExits reads selectors from the supplied controller endpoint and returns only verified live exits.
func dnsExits(ctx context.Context, client *http.Client, base string, cfg Config, domain string) ([]string, error) {
	name, err := dnsRoutingName(domain)
	if err != nil {
		return nil, err
	}
	decision := routing.Decide(cfg.Groups, cfg.Lists, cfg.Healthy, name)
	if decision.Outcome == routing.Reject || decision.Outcome == routing.RejectName {
		return nil, fmt.Errorf("invalid DNS routing context")
	}
	var exits []string
	for _, group := range cfg.Groups {
		if decision.Reason == routing.Matched && group.ID != decision.Group {
			continue
		}
		state, err := readSelector(ctx, client, base+"/proxies/"+url.PathEscape(group.ID))
		if err != nil || !state.matches(append([]string{deny}, group.Exits...)) || !cfg.Healthy[state.Now] {
			continue
		}
		if cfg.ConnectorKinds[state.Now] == "awg" && !AWGHeartbeatHealthy(state.Now) {
			continue
		}
		exits = append(exits, state.Now)
	}
	return exits, nil
}
