package panel

import (
	"errors"
	"net/http"
	"sync"
	"time"

	"github.com/Artik-Man/Hestia/internal/panelmodel"
	"github.com/danielgtaylor/huma/v2"
)

const (
	connectionOperationLimit     = 128
	connectionOperationRetention = time.Hour
)

// connectionOperationEntry retains one public receipt and its terminal retention timestamp.
type connectionOperationEntry struct {
	receipt     panelmodel.ConnectionEnabledOperation
	completedAt time.Time
}

// connectionOperationReceipts bounds process-local progress records without evicting running operations.
type connectionOperationReceipts struct {
	mu      sync.Mutex
	entries map[string]connectionOperationEntry
}

// begin reserves a UUID before helper dispatch, replays identical requests and rejects conflicting reuse.
func (r *connectionOperationReceipts) begin(operationID, id string, enabled bool, now time.Time) (panelmodel.ConnectionEnabledOperation, bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.entries == nil {
		r.entries = make(map[string]connectionOperationEntry)
	}
	for key, entry := range r.entries {
		if !entry.completedAt.IsZero() && now.Sub(entry.completedAt) >= connectionOperationRetention {
			delete(r.entries, key)
		}
	}
	if entry, ok := r.entries[operationID]; ok {
		if entry.receipt.ID != id || entry.receipt.Enabled != enabled {
			return panelmodel.ConnectionEnabledOperation{}, false, huma.Error409Conflict("UUID операции уже использован для другого изменения")
		}
		return entry.receipt, false, nil
	}
	if len(r.entries) >= connectionOperationLimit {
		oldest := ""
		var at time.Time
		for key, entry := range r.entries {
			if !entry.completedAt.IsZero() && (oldest == "" || entry.completedAt.Before(at)) {
				oldest, at = key, entry.completedAt
			}
		}
		if oldest == "" {
			return panelmodel.ConnectionEnabledOperation{}, false, huma.Error503ServiceUnavailable("Слишком много незавершённых операций")
		}
		delete(r.entries, oldest)
	}
	receipt := panelmodel.ConnectionEnabledOperation{OperationID: operationID, ID: id, Enabled: enabled, State: panelmodel.ConnectionOperationPending}
	r.entries[operationID] = connectionOperationEntry{receipt: receipt}
	return receipt, true, nil
}

// complete publishes the sanitized terminal status before the HTTP response can be lost.
func (r *connectionOperationReceipts) complete(operationID string, status int, now time.Time) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.entries[operationID]
	if !ok || entry.receipt.State != panelmodel.ConnectionOperationPending {
		return
	}
	entry.receipt.State = panelmodel.ConnectionOperationFailed
	if status == http.StatusOK {
		entry.receipt.State = panelmodel.ConnectionOperationSucceeded
	}
	entry.receipt.Status = status
	entry.completedAt = now
	r.entries[operationID] = entry
}

// get returns a copy of one retained receipt or forgets an expired terminal record.
func (r *connectionOperationReceipts) get(operationID string, now time.Time) (panelmodel.ConnectionEnabledOperation, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	entry, ok := r.entries[operationID]
	if ok && !entry.completedAt.IsZero() && now.Sub(entry.completedAt) >= connectionOperationRetention {
		delete(r.entries, operationID)
		ok = false
	}
	return entry.receipt, ok
}

// connectionOperationStatus retains only the public HTTP outcome, never an underlying helper detail.
func connectionOperationStatus(err error) int {
	if err == nil {
		return http.StatusOK
	}
	var status huma.StatusError
	if errors.As(err, &status) && status.GetStatus() >= 400 && status.GetStatus() <= 599 {
		return status.GetStatus()
	}
	return http.StatusInternalServerError
}

// replayConnectionOperation never dispatches a second helper for an already accepted UUID.
func replayConnectionOperation(receipt panelmodel.ConnectionEnabledOperation) (*connectionEnabledOutput, error) {
	switch receipt.State {
	case panelmodel.ConnectionOperationSucceeded:
		return &connectionEnabledOutput{Body: panelmodel.ConnectionEnabled{ID: receipt.ID, Enabled: receipt.Enabled}}, nil
	case panelmodel.ConnectionOperationFailed:
		return nil, huma.NewError(receipt.Status, "Операция изменения состояния завершилась ошибкой")
	default:
		return nil, huma.Error409Conflict("Операция изменения состояния ещё выполняется")
	}
}
