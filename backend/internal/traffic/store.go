package traffic

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	_ "modernc.org/sqlite"
)

var ErrSettingsConflict = errors.New("traffic settings changed")

var ErrQuery = errors.New("invalid traffic journal parameters")

// Store owns a local SQLite journal with ordered, durable ingest sequence numbers.
type Store struct {
	db        *sql.DB
	available atomic.Bool
}

const initialize = `
PRAGMA auto_vacuum=FULL;
CREATE TABLE IF NOT EXISTS policy (
  singleton INTEGER PRIMARY KEY CHECK(singleton=1),
  max_mb INTEGER NOT NULL, hours INTEGER NOT NULL, lost INTEGER NOT NULL
);
INSERT OR IGNORE INTO policy VALUES(1,1024,24,0);
CREATE TABLE IF NOT EXISTS source_state (
  singleton INTEGER PRIMARY KEY CHECK(singleton=1), last_interruption INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
  seq INTEGER PRIMARY KEY AUTOINCREMENT, stamp INTEGER NOT NULL, protocol TEXT NOT NULL,
  domain TEXT NOT NULL, address TEXT NOT NULL, fake_ip TEXT NOT NULL, kind TEXT NOT NULL,
  connection TEXT NOT NULL, event BLOB NOT NULL
);
CREATE INDEX IF NOT EXISTS events_time ON events(stamp,seq);
`

// Open initializes the private storage directory and removes expired history before serving requests.
func Open(dir string) (*Store, error) {
	if dir == "" {
		return nil, errors.New("traffic journal directory required")
	}
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, "journal.db")
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		return nil, err
	}
	if err = f.Close(); err != nil {
		return nil, err
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	store := &Store{db: db}
	if _, err = db.Exec(initialize); err == nil {
		err = store.Clean(context.Background())
	}
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return store, nil
}

// Close releases the database after collection and HTTP requests stop.
func (s *Store) Close() error { return s.db.Close() }

// SetAvailable reports whether the gateway event stream is currently connected.
func (s *Store) SetAvailable(available bool) { s.available.Store(available) }

// RecordInterruption persists the end of an established subscription independently of known event losses.
func (s *Store) RecordInterruption(ctx context.Context, at time.Time) error {
	_, err := s.db.ExecContext(ctx, "INSERT INTO source_state VALUES(1,?) ON CONFLICT(singleton) DO UPDATE SET last_interruption=MAX(last_interruption,excluded.last_interruption)", at.UnixMilli())
	return err
}

// RecordLoss adds observed input losses without counting ordinary age or quota eviction.
func (s *Store) RecordLoss(ctx context.Context, count int) error {
	if count < 0 {
		return ErrQuery
	}
	_, err := s.db.ExecContext(ctx, "UPDATE policy SET lost=lost+? WHERE singleton=1", count)
	return err
}

// Settings reads the currently committed storage limits.
func (s *Store) Settings(ctx context.Context) (TrafficSettings, error) {
	var settings TrafficSettings
	err := s.db.QueryRowContext(ctx, "SELECT max_mb,hours FROM policy WHERE singleton=1").Scan(&settings.MaxMB, &settings.RetentionHours)
	return settings, err
}

// SaveSettings commits new limits and eviction only if the settings read by the caller still match.
func (s *Store) SaveSettings(ctx context.Context, change TrafficSettingsChange) error {
	settings := change.Proposed
	if settings.MaxMB < 1 || settings.MaxMB > 1048576 || settings.RetentionHours < 1 || settings.RetentionHours > 87600 {
		return ErrQuery
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, "UPDATE policy SET max_mb=?,hours=? WHERE singleton=1 AND max_mb=? AND hours=?", settings.MaxMB, settings.RetentionHours, change.Expected.MaxMB, change.Expected.RetentionHours)
	if err != nil {
		return err
	}
	n, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if n != 1 {
		return ErrSettingsConflict
	}
	if err = prune(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

// Clean enforces both bounds when the stream is idle, including after a restart.
func (s *Store) Clean(ctx context.Context) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = prune(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

// prune evicts expired events and then the oldest rows until committed SQLite pages fit the quota.
func prune(ctx context.Context, tx *sql.Tx) error {
	var mb, hours int64
	if err := tx.QueryRowContext(ctx, "SELECT max_mb,hours FROM policy").Scan(&mb, &hours); err != nil {
		return err
	}
	cutoff := time.Now().Add(-time.Duration(hours) * time.Hour).UnixMilli()
	if _, err := tx.ExecContext(ctx, "DELETE FROM events WHERE stamp<?", cutoff); err != nil {
		return err
	}
	for {
		var stored int64
		if err := tx.QueryRowContext(ctx, "SELECT (page_count-freelist_count)*page_size FROM pragma_page_count,pragma_freelist_count,pragma_page_size").Scan(&stored); err != nil {
			return err
		}
		over := stored - mb*(1<<20)
		if over <= 0 {
			return nil
		}
		// FULL auto-vacuum releases freed pages on commit. Delete oldest first, including
		// under time ties; bounded batches also reclaim index pages on a large quota reduction.
		var count int64
		if err := tx.QueryRowContext(ctx, "SELECT count(*) FROM events").Scan(&count); err != nil {
			return err
		}
		batch := min(8192, max(1, int64(float64(count)*float64(over)/float64(stored))))
		res, err := tx.ExecContext(ctx, "DELETE FROM events WHERE seq IN (SELECT seq FROM events ORDER BY stamp,seq LIMIT ?)", batch)
		if err != nil {
			return err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return err
		}
		if n == 0 {
			return errors.New("traffic quota below database overhead")
		}
	}
}

// Append durably stores one observation and enforces retention in the same transaction.
func (s *Store) Append(ctx context.Context, event TrafficEvent) error {
	return s.AppendBatch(ctx, []TrafficEvent{event})
}

// AppendBatch commits one collector batch atomically with age and disk eviction.
func (s *Store) AppendBatch(ctx context.Context, events []TrafficEvent) error {
	if len(events) == 0 {
		return nil
	}
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	stmt, err := tx.PrepareContext(ctx, "INSERT INTO events(stamp,protocol,domain,address,fake_ip,kind,connection,event) VALUES(?,?,?,?,?,?,?,?)")
	if err != nil {
		return err
	}
	defer stmt.Close()
	for _, event := range events {
		if err = validateEvent(event); err != nil {
			return err
		}
		event.ID = ""
		data, err := json.Marshal(event)
		if err != nil {
			return err
		}
		if len(data) > 65536 {
			return errors.New("traffic event exceeds storage limit")
		}
		if _, err = stmt.ExecContext(ctx, event.Time.UnixMilli(), event.Protocol, strings.ToLower(event.Domain), strings.ToLower(event.Address), strings.ToLower(event.FakeIP), event.Kind, event.Connection, data); err != nil {
			return err
		}
	}
	if err = prune(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

// validateEvent rejects invented or malformed evidence before it can enter history.
func validateEvent(event TrafficEvent) error {
	if event.Time.IsZero() || (event.Protocol != "TCP" && event.Protocol != "UDP") || event.Port < 0 || event.Port > 65535 || (event.Address == "" && event.Domain == "" && event.FakeIP == "") {
		return errors.New("invalid traffic observation")
	}
	for _, addr := range []string{event.Address, event.FakeIP} {
		if addr != "" {
			if _, err := netip.ParseAddr(addr); err != nil {
				return fmt.Errorf("invalid traffic address: %w", err)
			}
		}
	}
	if len(event.Connection) > 500 || len(event.Domain) > 255 {
		return errors.New("traffic identifier too long")
	}
	if event.Trace != nil {
		trace := event.Trace
		source, sourceErr := netip.ParseAddr(trace.Source)
		destination, destinationErr := netip.ParseAddr(trace.Destination)
		policyDigits := strings.TrimPrefix(trace.PolicyKey, "Policy")
		validPolicyKey := trace.PolicyKey == "" || len(trace.PolicyKey) >= 7 && len(trace.PolicyKey) <= 16 && policyDigits != trace.PolicyKey && policyDigits != ""
		for _, digit := range policyDigits {
			validPolicyKey = validPolicyKey && digit >= '0' && digit <= '9'
		}
		if sourceErr != nil || destinationErr != nil || !source.Is4() || !destination.Is4() || trace.DurationMs < 0 || trace.DurationMs > 15000 || trace.SourcePort < 1 || trace.SourcePort > 65535 || trace.DestinationPort < 1 || trace.DestinationPort > 65535 || len(trace.SessionID) > 64 || !validPolicyKey || trace.ConfiguredMark > 0x0fffffff || trace.NDMTable > 65535 || trace.HestiaTable > 65535 || len(trace.Stages) > MaxTraceStages {
			return errors.New("invalid traffic trace summary")
		}
		for _, stage := range trace.Stages {
			if len(stage.Name) > 32 || len(stage.Detail) > 160 || stage.Count < 0 || stage.ReverseCount < 0 || (stage.Status != "observed" && stage.Status != "not_observed" && stage.Status != "configured_expectation" && stage.Status != "unavailable" && stage.Status != "truncated") {
				return errors.New("invalid traffic trace stage")
			}
		}
		if trace.NDMConntrack != nil {
			if err := validateTraceNDMConntrack(trace.NDMConntrack); err != nil {
				return err
			}
		}
	}
	if event.Kind != Observed && event.NetworkInterface != "" {
		return errors.New("unconfirmed traffic interface")
	}
	switch event.Kind {
	case Observed:
		if event.Connection == "" || event.NetworkInterface == "" {
			return errors.New("missing observed exit")
		}
	case Blocked:
		if event.BlockReason == "" {
			return errors.New("missing block reason")
		}
	case Unconfirmed:
	default:
		return errors.New("invalid traffic result")
	}
	return nil
}

// validateTraceNDMConntrack accepts only sanitized states and allowlisted fields from one exact NDM conntrack record.
func validateTraceNDMConntrack(evidence *NDMConntrackEvidence) error {
	if evidence == nil || evidence.ObservedAt.IsZero() || len(evidence.Detail) > 160 || len(evidence.Flags) > 4 {
		return errors.New("invalid NDM conntrack trace evidence")
	}
	if (evidence.Mark != nil && *evidence.Mark > 0xffffffff) || (evidence.NDMMark != nil && *evidence.NDMMark > 0xffffffff) {
		return errors.New("NDM conntrack mark exceeds uint32")
	}
	switch evidence.Status {
	case "observed":
		if evidence.OriginalPackets == nil || evidence.OriginalBytes == nil {
			return errors.New("incomplete NDM conntrack trace evidence")
		}
	case "not_observed", "unavailable", "truncated":
		if evidence.OriginalPackets != nil || evidence.OriginalBytes != nil || evidence.ReplyPackets != nil || evidence.ReplyBytes != nil || evidence.Mark != nil || evidence.NDMMark != nil || evidence.IFL != nil || evidence.IFW != nil || evidence.IFLName != "" || evidence.IFWName != "" || len(evidence.Flags) != 0 {
			return errors.New("non-observed NDM conntrack stage contains flow fields")
		}
	default:
		return errors.New("invalid NDM conntrack trace status")
	}
	for _, name := range []string{evidence.IFLName, evidence.IFWName} {
		if name != "" && name != "br0" && name != "opkgtun0" {
			return errors.New("invalid NDM conntrack interface name")
		}
	}
	seenFlags := make(map[string]struct{}, len(evidence.Flags))
	for _, flag := range evidence.Flags {
		if flag != "ASSURED" && flag != "UNREPLIED" && flag != "SEEN_REPLY" && flag != "FASTNAT" {
			return errors.New("invalid NDM conntrack flag")
		}
		if _, exists := seenFlags[flag]; exists {
			return errors.New("duplicate NDM conntrack flag")
		}
		seenFlags[flag] = struct{}{}
	}
	return nil
}

// Page returns recent events first and applies filters before pagination; new inserts cannot move a snapshot.
func (s *Store) Page(ctx context.Context, q Query) (TrafficPage, error) {
	page := TrafficPage{Events: []TrafficEvent{}, Outputs: []string{}, SourceAvailable: s.available.Load()}
	if q.Limit < 1 || q.Limit > 500 || q.Offset < 0 || (q.Protocol != "" && q.Protocol != "UDP" && q.Protocol != "TCP") || (!q.From.IsZero() && !q.Until.IsZero() && q.From.After(q.Until)) {
		return page, ErrQuery
	}
	tx, err := s.db.BeginTx(ctx, &sql.TxOptions{ReadOnly: true})
	if err != nil {
		return page, err
	}
	defer tx.Rollback()
	var high int64
	// AUTOINCREMENT retains the high-water mark even when cleanup empties the table.
	if err = tx.QueryRowContext(ctx, "SELECT COALESCE((SELECT seq FROM sqlite_sequence WHERE name='events'),0)").Scan(&high); err != nil {
		return page, err
	}
	if q.Snapshot != "" {
		seq, e := strconv.ParseInt(q.Snapshot, 10, 64)
		if e != nil || seq < 0 || seq > high {
			return page, ErrQuery
		}
		high = seq
	}
	page.Snapshot = strconv.FormatInt(high, 10)
	var hours int
	var interruption sql.NullInt64
	if err = tx.QueryRowContext(ctx, "SELECT hours,lost,(SELECT last_interruption FROM source_state WHERE singleton=1) FROM policy").Scan(&hours, &page.Lost, &interruption); err != nil {
		return page, err
	}
	if interruption.Valid {
		at := time.UnixMilli(interruption.Int64).UTC()
		page.LastInterruption = &at
	}
	from := time.Now().Add(-time.Duration(hours) * time.Hour)
	if q.From.After(from) {
		from = q.From
	}
	until := q.Until
	if until.IsZero() {
		until = time.Now()
	}
	where := " FROM events WHERE seq<=? AND stamp BETWEEN ? AND ?"
	args := []any{high, from.UnixMilli(), until.UnixMilli()}
	rows, err := tx.QueryContext(ctx, "SELECT DISTINCT connection"+where+" AND connection<>'' ORDER BY connection", args...)
	if err != nil {
		return page, err
	}
	for rows.Next() {
		var id string
		if err = rows.Scan(&id); err != nil {
			rows.Close()
			return page, err
		}
		page.Outputs = append(page.Outputs, id)
	}
	if err = rows.Err(); err != nil {
		rows.Close()
		return page, err
	}
	rows.Close()
	if q.Protocol != "" {
		where += " AND protocol=?"
		args = append(args, q.Protocol)
	}
	switch {
	case q.Output == "":
	case q.Output == Blocked || q.Output == Unconfirmed:
		where += " AND kind=?"
		args = append(args, q.Output)
	case strings.HasPrefix(q.Output, ConnectionFilter) && len(q.Output) > len(ConnectionFilter):
		where += " AND connection=?"
		args = append(args, strings.TrimPrefix(q.Output, ConnectionFilter))
	default:
		return page, ErrQuery
	}
	if term := strings.ToLower(strings.TrimSpace(q.Text)); term != "" {
		where += " AND (instr(domain,?)>0 OR instr(address,?)>0 OR instr(fake_ip,?)>0)"
		args = append(args, term, term, term)
	}
	var matched map[int64]string
	if q.MatchCountry != nil {
		matched, page.Total, err = countryWindow(ctx, tx, where, args, q)
		if err != nil {
			return page, err
		}
		if len(matched) == 0 {
			return page, tx.Commit()
		}
		where = " FROM events WHERE seq IN (" + strings.Repeat("?,", len(matched)-1) + "?)"
		args = make([]any, 0, len(matched))
		for seq := range matched {
			args = append(args, seq)
		}
		q.Offset = 0
	} else if err = tx.QueryRowContext(ctx, "SELECT count(*)"+where, args...).Scan(&page.Total); err != nil {
		return page, err
	}
	rows, err = tx.QueryContext(ctx, "SELECT seq,event"+where+" ORDER BY stamp DESC,seq DESC LIMIT ? OFFSET ?", append(args, q.Limit, q.Offset)...)
	if err != nil {
		return page, err
	}
	defer rows.Close()
	for rows.Next() {
		var seq int64
		var data []byte
		if err = rows.Scan(&seq, &data); err != nil {
			return page, err
		}
		var e TrafficEvent
		if err = json.Unmarshal(data, &e); err != nil {
			return page, err
		}
		e.ID = strconv.FormatInt(seq, 10)
		if matched != nil {
			e.Country = matched[seq]
		}
		page.Events = append(page.Events, e)
	}
	if err = rows.Err(); err != nil {
		return page, err
	}
	return page, tx.Commit()
}

// countryWindow counts all matching destinations but retains only the requested window of IDs and their resolved countries.
func countryWindow(ctx context.Context, tx *sql.Tx, where string, args []any, q Query) (map[int64]string, int, error) {
	rows, err := tx.QueryContext(ctx, "SELECT seq,address,fake_ip"+where+" ORDER BY stamp DESC,seq DESC", args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	selected := make(map[int64]string)
	total := 0
	for rows.Next() {
		var seq int64
		var address, fakeIP string
		if err := rows.Scan(&seq, &address, &fakeIP); err != nil {
			return nil, 0, err
		}
		code, matches := q.MatchCountry(address, fakeIP)
		if !matches {
			continue
		}
		if total >= q.Offset && len(selected) < q.Limit {
			selected[seq] = code
		}
		total++
	}
	return selected, total, rows.Err()
}
