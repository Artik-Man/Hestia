package observer

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"time"
)

type probeFunc func(context.Context, Connection, Target, time.Duration) Probe

// Run checks Linux interfaces, then reports each scope in input order until canceled or the requested rounds finish.
func Run(ctx context.Context, s Settings, rounds int, output io.Writer) error {
	encoder := json.NewEncoder(output)
	return runReports(ctx, s, rounds, func(r Report) error { return encoder.Encode(r) })
}

// runReports validates runtime prerequisites and passes each typed report to its consumer.
func runReports(ctx context.Context, s Settings, rounds int, emit func(Report) error) error {
	if rounds < 0 {
		return fmt.Errorf("rounds must be nonnegative")
	}
	if err := s.validate(); err != nil {
		return err
	}
	if runtime.GOOS != "linux" {
		return fmt.Errorf("interface-bound observation requires Linux")
	}
	for _, c := range s.Connections {
		if _, err := net.InterfaceByName(c.Interface); err != nil {
			return fmt.Errorf("connection %q: %w", c.ID, err)
		}
	}
	return run(ctx, s, rounds, emit, measure)
}

// run takes joint rounds and skips missed schedule slots instead of sending catch-up probes.
func run(ctx context.Context, s Settings, rounds int, emit func(Report) error, probe probeFunc) error {
	scopes := make([]*history, len(s.Targets))
	for i, t := range s.Targets {
		scopes[i] = newHistory(s, t)
	}
	next := time.Now()
	for round := 1; rounds == 0 || round <= rounds; round++ {
		if ctx.Err() != nil {
			return nil
		}
		start := time.Now()
		result := collect(ctx, s, probe)
		if ctx.Err() != nil {
			return nil
		}
		for i, h := range scopes {
			if err := emit(h.observe(start, result[i])); err != nil {
				return err
			}
		}
		if rounds != 0 && round == rounds {
			break
		}
		next = next.Add(s.Interval)
		if elapsed := time.Since(next); elapsed >= 0 {
			next = next.Add((elapsed/s.Interval + 1) * s.Interval)
		}
		timer := time.NewTimer(time.Until(next))
		select {
		case <-timer.C:
		case <-ctx.Done():
			timer.Stop()
			return nil
		}
	}
	return nil
}

// collect joins one simultaneous batch of probes; each goroutine owns one output slot.
func collect(ctx context.Context, s Settings, probe probeFunc) [][]Probe {
	rows := make([][]Probe, len(s.Targets))
	var wg sync.WaitGroup
	for i, t := range s.Targets {
		rows[i] = make([]Probe, len(s.Connections))
		for j, c := range s.Connections {
			wg.Add(1)
			go func() { defer wg.Done(); rows[i][j] = probe(ctx, c, t, s.Timeout) }()
		}
	}
	wg.Wait()
	return rows
}
