package controller

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"runtime"
	"slices"
	"time"

	"github.com/Artik-Man/Hestia/internal/observer"
	"github.com/Artik-Man/Hestia/internal/routing"
)

type balanceResult struct {
	Time        time.Time         `json:"time"`
	Group       string            `json:"group"`
	Current     string            `json:"current"`
	Recommended string            `json:"recommended"`
	Applied     string            `json:"applied"`
	Reason      string            `json:"reason"`
	Votes       []string          `json:"votes"`
	Consecutive int               `json:"consecutive"`
	Required    int               `json:"confirm_rounds"`
	Probes      []observer.Report `json:"probes"`
	Error       string            `json:"error,omitempty"`
}

type balanceState struct {
	candidate string
	witnesses []string
	rounds    int
}

// RunBalanceCLI samples independent IP targets and updates a single preconfigured group's selector on sustained agreement.
func RunBalanceCLI(ctx context.Context, args []string, out, diagnostics io.Writer) error {
	flags := flag.NewFlagSet("hestia balance", flag.ContinueOnError)
	flags.SetOutput(diagnostics)
	path := flags.String("config", "", "observer configuration")
	rounds := flags.Int("rounds", 0, "number of rounds; zero continues until stopped")
	confirm := flags.Int("confirm-rounds", 3, "consecutive qualifying rounds")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *path == "" || flags.NArg() != 0 || *rounds < 0 || *confirm < 1 || *confirm > 1000 {
		return fmt.Errorf("usage: hestia balance -config FILE [-rounds N] [-confirm-rounds 1..1000]")
	}
	if runtime.GOOS != "linux" {
		return fmt.Errorf("group balancing requires Linux")
	}
	s, err := observer.ReadSettings(*path)
	if err != nil {
		return err
	}
	group, err := balanceGroup(s)
	if err != nil {
		return err
	}
	lock, err := groupLock(group.ID)
	if err != nil {
		return fmt.Errorf("reserve selector: %w", err)
	}
	defer lock.Close()
	client := newClient()
	defer client.CloseIdleConnections()
	encoder := json.NewEncoder(out)
	batch := make([]observer.Report, 0, len(s.Targets))
	state := &balanceState{}
	return observer.RunReports(ctx, s, *rounds, func(r observer.Report) error {
		batch = append(batch, r)
		if len(batch) < len(s.Targets) {
			return nil
		}
		result, applyErr := state.balance(ctx, client, localAPI, s, group, batch, *confirm)
		if applyErr != nil {
			result.Error = applyErr.Error()
		}
		logErr := encoder.Encode(result)
		batch = batch[:0]
		return errors.Join(applyErr, logErr)
	})
}

// balanceGroup validates selector tag membership and enforces a minimum of two distinct destination addresses.
func balanceGroup(s observer.Settings) (routing.Group, error) {
	group := routing.Group{ID: s.Group}
	if len(s.Connections) != 2 {
		return group, fmt.Errorf("balance requires exactly two connections")
	}
	for _, c := range s.Connections {
		group.Exits = append(group.Exits, c.ID)
	}
	cfg := Config{Groups: []routing.Group{group}, Healthy: map[string]bool{}}
	if err := cfg.validate(); err != nil {
		return group, err
	}
	ips := map[string]bool{}
	for _, target := range s.Targets {
		ips[target.Address] = true
	}
	if len(ips) < 2 {
		return group, fmt.Errorf("balance requires at least two distinct IPv4 destinations")
	}
	return group, nil
}

// balanceVotes compares the candidate's paired delivery with the actual current exit, counting each IP at most once.
func balanceVotes(s observer.Settings, batch []observer.Report, current, alt string) ([]string, string) {
	ips := map[string]bool{}
	opposing := map[string]bool{}
	shared := map[string]bool{}
	for _, r := range batch {
		a, b := r.Counts[current], r.Counts[alt]
		switch {
		case r.Latest[current].Status == observer.LocalError || r.Latest[alt].Status == observer.LocalError:
			return []string{}, "local_error"
		case r.Samples < s.MinSamples:
			return []string{}, "insufficient_samples"
		case a.Received+b.Received == 0 || (r.Latest[current].Status == observer.Lost && r.Latest[alt].Status == observer.Lost):
			shared[r.Address] = true
		case (a.Received-b.Received)*100 >= r.Samples*s.MarginPercent:
			opposing[r.Address] = true
		case (b.Received-a.Received)*100 >= r.Samples*s.MarginPercent:
			ips[r.Address] = true
		}
	}
	votes := make([]string, 0, len(ips))
	for ip := range ips {
		if !shared[ip] {
			votes = append(votes, ip)
		}
	}
	slices.Sort(votes)
	for ip := range opposing {
		if !shared[ip] {
			return votes, "opposing_evidence"
		}
	}
	if len(votes) < 2 && len(shared) > 0 {
		return votes, "shared_failure"
	}
	if len(votes) < 2 {
		return votes, "no_quorum"
	}
	return votes, "qualifies"
}

// confirm counts consecutive rounds in which at least two of the same IPs still favor the same alternate.
func (st *balanceState) confirm(alt string, votes []string) {
	common := []string{}
	if st.candidate == alt {
		for _, ip := range st.witnesses {
			if slices.Contains(votes, ip) {
				common = append(common, ip)
			}
		}
	}
	if len(common) < 2 {
		st.candidate, st.witnesses, st.rounds = alt, slices.Clone(votes), 1
		return
	}
	st.witnesses = common
	st.rounds++
}

// balance reads the actual selector, evaluates the completed round and reports only a read-back-confirmed switch.
func (st *balanceState) balance(parent context.Context, client *http.Client, base string, s observer.Settings, group routing.Group, batch []observer.Report, confirm int) (balanceResult, error) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	result := balanceResult{Time: batch[0].Time, Group: group.ID, Applied: "unknown", Reason: "selector_error", Required: confirm, Probes: batch, Votes: []string{}}
	endpoint := base + "/proxies/" + url.PathEscape(group.ID)
	sel, err := readSelector(ctx, client, endpoint)
	if err != nil {
		return result, err
	}
	members := append([]string{deny}, group.Exits...)
	if !sel.matches(members) {
		return result, fmt.Errorf("unexpected membership for %s", group.ID)
	}
	result.Current, result.Recommended, result.Applied = sel.Now, sel.Now, sel.Now
	if sel.Now == deny {
		*st = balanceState{}
		result.Reason = "deny_active"
		return result, nil
	}
	alt := group.Exits[0]
	if alt == sel.Now {
		alt = group.Exits[1]
	}
	votes, reason := balanceVotes(s, batch, sel.Now, alt)
	result.Votes, result.Reason = votes, reason
	if reason != "qualifies" {
		*st = balanceState{}
		return result, nil
	}
	st.confirm(alt, votes)
	result.Consecutive = st.rounds
	result.Votes = slices.Clone(st.witnesses)
	if st.rounds < confirm {
		result.Reason = "confirming"
		return result, nil
	}
	result.Recommended, result.Applied, result.Reason = alt, "unknown", "selector_error"
	if err := setTarget(ctx, client, endpoint, alt); err != nil {
		return result, fmt.Errorf("selector write unconfirmed: %w", err)
	}
	actual, err := readSelector(ctx, client, endpoint)
	if err != nil {
		return result, fmt.Errorf("selector readback: %w", err)
	}
	if !actual.matches(members) || actual.Now != alt {
		return result, fmt.Errorf("expected %s, received %s", alt, actual.Now)
	}
	*st = balanceState{}
	result.Applied, result.Reason = alt, "better_delivery"
	return result, nil
}
