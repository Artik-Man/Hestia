package trafficcapture

import (
	"context"
	"log"
	"time"

	"github.com/Artik-Man/Hestia/internal/traffic"
	"golang.org/x/net/websocket"
)

const gatewayLog = "ws://127.0.0.1:9090/logs?level=debug"
const batchSize = 64

// journal accepts complete event batches and separately exposes stream availability and known losses.
type journal interface {
	AppendBatch(context.Context, []traffic.TrafficEvent) error
	RecordLoss(context.Context, int) error
	RecordInterruption(context.Context, time.Time) error
	SetAvailable(bool)
}

// Run consumes the installed gateway's loopback-only Clash subscription until cancellation.
// Reconnecting establishes a fresh attribution scope; the upstream offers no history replay.
func Run(ctx context.Context, store journal) {
	run(ctx, gatewayLog, store)
}

// run retries a bounded handshake and keeps unreported storage losses across reconnects.
func run(ctx context.Context, endpoint string, sink journal) {
	cfg, err := websocket.NewConfig(endpoint, "http://127.0.0.1")
	if err != nil {
		return
	}
	lost := 0
	for ctx.Err() == nil {
		dialCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
		conn, err := cfg.DialContext(dialCtx)
		cancel()
		if err == nil {
			sink.SetAvailable(true)
			consume(ctx, conn, sink, &lost)
			sink.SetAvailable(false)
			recordCtx, stop := context.WithTimeout(context.WithoutCancel(ctx), 2*time.Second)
			if err := sink.RecordInterruption(recordCtx, time.Now().UTC()); err != nil {
				log.Print("traffic capture: cannot save subscription interruption")
			}
			stop()
		}
		select {
		case <-ctx.Done():
			return
		case <-time.After(2 * time.Second):
		}
	}
}

// logMessage carries only the upstream payload and the local time it was received.
type logMessage struct {
	payload  string
	received time.Time
}

// readLogs decodes bounded WebSocket frames until disconnect or cancellation.
func readLogs(conn *websocket.Conn, messages chan<- logMessage) {
	defer close(messages)
	for {
		var entry struct {
			Payload string `json:"payload"`
		}
		if err := websocket.JSON.Receive(conn, &entry); err != nil {
			return
		}
		messages <- logMessage{entry.Payload, time.Now().UTC()}
	}
}

// consume scopes pending flows to one source connection, flushes partial observations and bounded batches.
func consume(ctx context.Context, conn *websocket.Conn, sink journal, lost *int) {
	conn.MaxPayloadBytes = 64 << 10
	defer conn.Close()
	// Stop the socket read, then drain every message already decoded before shutting down storage.
	stopRead := context.AfterFunc(ctx, func() { _ = conn.SetReadDeadline(time.Now()) })
	defer stopRead()
	messages := make(chan logMessage, 128)
	go readLogs(conn, messages)
	persistMessages(ctx, messages, sink, lost)
}

// persistMessages drains the decoded stream, including pending attribution, before returning to the subscriber.
func persistMessages(ctx context.Context, messages <-chan logMessage, sink journal, lost *int) {
	batch := make([]traffic.TrafficEvent, 0, batchSize)
	// Let an in-flight transaction finish after the stop signal; all remaining batches share this grace period.
	writeCtx, stopWrites := context.WithCancel(context.WithoutCancel(ctx))
	defer stopWrites()
	stopGrace := context.AfterFunc(ctx, func() { time.AfterFunc(2*time.Second, stopWrites) })
	defer stopGrace()
	flush := func() {
		if len(batch) > 0 {
			if err := sink.AppendBatch(writeCtx, batch); err != nil {
				if *lost == 0 {
					log.Print("traffic capture: cannot save event batch")
				}
				*lost += len(batch)
			}
			batch = batch[:0]
		}
		if *lost > 0 && sink.RecordLoss(writeCtx, *lost) == nil {
			*lost = 0
		}
	}
	parser := newParser(func(event traffic.TrafficEvent) {
		batch = append(batch, event)
		if len(batch) >= batchSize {
			flush()
		}
	})
	defer func() {
		parser.flushBefore(time.Now())
		flush()
	}()
	tick := time.NewTicker(250 * time.Millisecond)
	defer tick.Stop()
	for {
		select {
		case message, ok := <-messages:
			if !ok {
				return
			}
			parser.accept(message.received, message.payload)
		case now := <-tick.C:
			parser.flushBefore(now.Add(-attributionWindow))
			flush()
		}
	}
}
