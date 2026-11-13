package panelmodel

import (
	"encoding/json"
	"errors"
)

// ConnectionEnabledRequest sets administrative availability independently of probe health.
type ConnectionEnabledRequest struct {
	Enabled     bool                  `json:"enabled"`
	OperationID ConnectionOperationID `json:"operationId,omitempty" minLength:"36" maxLength:"36" pattern:"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$" doc:"UUID одной попытки изменения; повтор не запускает операцию заново."`
}

// ConnectionEnabled confirms the committed state of one stable virtual connection ID.
type ConnectionEnabled struct {
	ID      string `json:"id" minLength:"1" maxLength:"63"`
	Enabled bool   `json:"enabled"`
}

// ConnectionOperationState distinguishes an active helper from its terminal public outcome.
type ConnectionOperationState string

const (
	// ConnectionOperationPending means the helper has not returned a terminal result.
	ConnectionOperationPending ConnectionOperationState = "pending"
	// ConnectionOperationSucceeded means the helper returned the matching committed state.
	ConnectionOperationSucceeded ConnectionOperationState = "succeeded"
	// ConnectionOperationFailed means the helper ended without a matching successful acknowledgement.
	ConnectionOperationFailed ConnectionOperationState = "failed"
)

// ConnectionEnabledOperation is a bounded public receipt; it contains no profile, helper output or credential.
type ConnectionEnabledOperation struct {
	OperationID string                   `json:"operationId" minLength:"36" maxLength:"36"`
	ID          string                   `json:"id" minLength:"1" maxLength:"63"`
	Enabled     bool                     `json:"enabled"`
	State       ConnectionOperationState `json:"state" enum:"pending,succeeded,failed"`
	Status      int                      `json:"status,omitempty" minimum:"100" maximum:"599" doc:"HTTP-статус завершённой операции; отсутствует, пока helper работает."`
}

// ConnectionOperationID distinguishes an omitted receipt UUID from an explicitly empty or null value.
type ConnectionOperationID string

// UnmarshalJSON requires a nonempty string; the public request schema additionally validates UUID syntax.
func (id *ConnectionOperationID) UnmarshalJSON(data []byte) error {
	var value string
	if json.Unmarshal(data, &value) != nil || value == "" {
		return errors.New("operationId must be a nonempty UUID string")
	}
	*id = ConnectionOperationID(value)
	return nil
}
