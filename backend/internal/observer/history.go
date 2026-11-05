package observer

import "time"

type Counts struct {
	Sent     int `json:"sent"`
	Received int `json:"received"`
	Lost     int `json:"lost"`
}

type Report struct {
	Time  time.Time `json:"time"`
	Group string    `json:"group"`
	Target
	Window      string            `json:"window"`
	Current     string            `json:"current"`
	Recommended string            `json:"recommended"`
	Reason      string            `json:"reason"`
	Samples     int               `json:"samples"`
	Counts      map[string]Counts `json:"counts"`
	Latest      map[string]Probe  `json:"latest"`
}

type paired struct {
	at        time.Time
	delivered uint32
}

type history struct {
	settings Settings
	target   Target
	rows     []paired
	received []int
	current  int
}

// newHistory starts one independent IP/protocol comparison in configured priority order.
func newHistory(s Settings, t Target) *history {
	return &history{settings: s, target: t, received: make([]int, len(s.Connections))}
}

// observe expires stale evidence and adds one complete paired round to the scoped comparison.
func (h *history) observe(at time.Time, probes []Probe) Report {
	s := h.settings
	cutoff := at.Add(-s.Window)
	for len(h.rows) > 0 && !h.rows[0].at.After(cutoff) {
		old := h.rows[0]
		for i := range h.received {
			if old.delivered&(1<<i) != 0 {
				h.received[i]--
			}
		}
		h.rows = h.rows[1:]
	}
	r := Report{Time: at.UTC(), Group: s.Group, Target: h.target, Window: s.Window.String(), Current: s.Connections[h.current].ID,
		Latest: make(map[string]Probe, len(probes)), Counts: make(map[string]Counts, len(probes))}
	var row paired
	row.at = at
	valid := true
	for i, p := range probes {
		r.Latest[s.Connections[i].ID] = p
		switch p.Status {
		case Received:
			row.delivered |= 1 << i
		case Lost:
		default:
			valid = false
		}
	}
	if valid {
		h.rows = append(h.rows, row)
		for i := range h.received {
			if row.delivered&(1<<i) != 0 {
				h.received[i]++
			}
		}
	}
	r.Samples = len(h.rows)
	for i, c := range s.Connections {
		r.Counts[c.ID] = Counts{Sent: r.Samples, Received: h.received[i], Lost: r.Samples - h.received[i]}
	}
	r.Reason = h.recommend(valid)
	r.Recommended = s.Connections[h.current].ID
	return r
}

// recommend holds the current path on equality or insufficient evidence; ties among better paths use configured order.
func (h *history) recommend(valid bool) string {
	n := len(h.rows)
	if !valid {
		return "local_error"
	}
	if n < h.settings.MinSamples {
		return "insufficient_samples"
	}
	best := h.current
	for i, count := range h.received {
		if count > h.received[best] {
			best = i
		}
	}
	if best == h.current {
		return "hold_current"
	}
	if (h.received[best]-h.received[h.current])*100 < n*h.settings.MarginPercent {
		return "margin_not_met"
	}
	h.current = best
	return "better_delivery"
}
