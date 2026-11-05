// Package dnspolicy selects names for DNS warmup from client demand and administrator policy.
package dnspolicy

import (
	"errors"
	"maps"
	"slices"
)

// Selection contains the sorted automatic list for display and the distinct names eligible for refresh.
type Selection struct {
	Automatic []string
	Effective []string
}

// SelectWarmDomains evaluates a snapshot without modifying it. Counts must represent real client
// requests in the current activity window; all names must use the same canonical DNS spelling.
// Exclusions suppress only automatic membership. A nonpositive threshold returns an error.
func SelectWarmDomains(threshold int, clientCounts map[string]int, manual, excluded []string) (Selection, error) {
	if threshold < 1 {
		return Selection{}, errors.New("DNS warmup threshold must be positive")
	}
	blocked := make(map[string]bool, len(excluded))
	for _, name := range excluded {
		blocked[name] = true
	}
	effective := make(map[string]bool, len(manual))
	for _, name := range manual {
		effective[name] = true
	}
	automatic := make([]string, 0)
	for name, count := range clientCounts {
		if count >= threshold && !blocked[name] {
			automatic = append(automatic, name)
			effective[name] = true
		}
	}
	slices.Sort(automatic)
	return Selection{Automatic: automatic, Effective: slices.Sorted(maps.Keys(effective))}, nil
}
