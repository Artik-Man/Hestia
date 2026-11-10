//go:build linux && arm64 && !android && keenetic

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/Artik-Man/Hestia/internal/storage"
	"github.com/Artik-Man/Hestia/internal/traffic"
	"github.com/Artik-Man/Hestia/internal/trafficcapture"
)

// runTrafficTraceCommand performs one explicitly requested bounded capture and writes its summary to the journal and stdout.
func runTrafficTraceCommand(input io.Reader, output io.Writer) error {
	if os.Geteuid() != 0 {
		return errors.New("traffic trace requires root")
	}
	data, err := io.ReadAll(io.LimitReader(input, 2049))
	if err != nil {
		return err
	}
	request, err := trafficcapture.DecodeTraceRequest(data)
	if err != nil {
		return err
	}
	lock, err := acquireTrafficTraceLock()
	if err != nil {
		return err
	}
	defer lock.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(request.DurationSeconds+8)*time.Second)
	defer cancel()
	expectationContext, cancelExpectation := context.WithTimeout(ctx, 5*time.Second)
	expectation := trafficcapture.ReadTraceConfigurationForCommand(expectationContext, request.Source)
	cancelExpectation()
	result := trafficcapture.CaptureTrace(ctx, request)
	conntrackContext, cancelConntrack := context.WithTimeout(ctx, 2*time.Second)
	result.NDMConntrack = trafficcapture.ReadNDMConntrack(conntrackContext, request)
	cancelConntrack()
	result.PolicyKey = expectation.PolicyKey
	result.ConfigurationObservedAt = &expectation.ObservedAt
	result.ConfiguredMark = expectation.ConfiguredMark
	result.NDMTable = expectation.NDMTable
	result.HestiaTable = expectation.HestiaTable
	result.Stages = append(result.Stages, expectation.Stages...)
	stages := make([]traffic.TraceStage, 0, len(result.Stages))
	for _, stage := range result.Stages {
		stages = append(stages, traffic.TraceStage{Name: stage.Name, Status: stage.Status, Detail: stage.Detail, Count: stage.Count, ReverseCount: stage.ReverseCount})
	}
	trace := &traffic.TraceEvidence{SessionID: result.StartedAt.Format("20060102T150405.000000000Z"), StartedAt: result.StartedAt, ConfigurationObservedAt: result.ConfigurationObservedAt, DurationMs: result.DurationMs, PolicyKey: result.PolicyKey, ConfiguredMark: result.ConfiguredMark, NDMTable: result.NDMTable, HestiaTable: result.HestiaTable, Source: result.Source, SourcePort: result.SourcePort, Destination: result.Destination, DestinationPort: result.DestinationPort, NDMConntrack: result.NDMConntrack, Stages: stages}
	event := traffic.TrafficEvent{Time: result.StartedAt, Protocol: result.Protocol, Address: result.Destination, Port: result.DestinationPort, Kind: traffic.Unconfirmed, Reason: "opt-in flow trace summary", Trace: trace}
	store, err := traffic.Open(storage.Installed().Traffic)
	if err != nil {
		return fmt.Errorf("open traffic journal: %w", err)
	}
	defer store.Close()
	if err := store.Append(ctx, event); err != nil {
		return fmt.Errorf("save traffic trace: %w", err)
	}
	return json.NewEncoder(output).Encode(result)
}

// acquireTrafficTraceLock allows only one concurrent tuple capture and keeps the lock file root-only.
func acquireTrafficTraceLock() (*os.File, error) {
	path := filepath.Join(storage.Installed().Runtime, "traffic-trace.lock")
	file, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm() != 0600 {
		_ = file.Close()
		return nil, errors.New("traffic trace lock path is not a root-only regular file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || stat.Uid != 0 {
		_ = file.Close()
		return nil, errors.New("traffic trace lock is not root-owned")
	}
	if err := syscall.Flock(int(file.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		_ = file.Close()
		return nil, errors.New("another traffic trace session is active")
	}
	return file, nil
}

// trafficTraceEnabled exposes the diagnostic command only in the Keenetic build.
func trafficTraceEnabled() bool { return true }
