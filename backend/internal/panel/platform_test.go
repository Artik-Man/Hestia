package panel

import (
	"context"
	"encoding/json"
	"io"
	"testing"

	"github.com/Artik-Man/Hestia/internal/panelmodel"
	"github.com/Artik-Man/Hestia/internal/platformhelper"
)

// helperCapture records the semantic privilege request without running a process.
type helperCapture struct {
	mode   platformhelper.Mode
	data   []byte
	policy platformhelper.Cancellation
}

// Execute captures stdin data and cancellation policy selected by the real panel writer.
func (h *helperCapture) Execute(_ context.Context, mode platformhelper.Mode, data []byte, _ io.Writer, policy platformhelper.Cancellation) error {
	h.mode, h.data, h.policy = mode, append([]byte(nil), data...), policy
	return nil
}

// TestPanelWritersSelectPrivilegeContracts checks the actual routing and secret-profile writer boundaries.
func TestPanelWritersSelectPrivilegeContracts(t *testing.T) {
	old := installedHelperTransport
	capture := &helperCapture{}
	installedHelperTransport = capture
	t.Cleanup(func() { installedHelperTransport = old })
	change := panelmodel.BindingChange{ListID: "list", Group: "group"}
	if err := applyInstalledBinding(context.Background(), change); err != nil {
		t.Fatal(err)
	}
	if capture.mode != "-apply-binding" || capture.policy != platformhelper.Transaction {
		t.Fatal("routing cancellation contract lost")
	}
	var decoded panelmodel.BindingChange
	if json.Unmarshal(capture.data, &decoded) != nil || decoded != change {
		t.Fatal("routing payload changed")
	}
	if err := runAWGHelper(context.Background(), "-awg-delete", panelmodel.AWGIDRequest{ID: "fi-1"}, nil); err != nil {
		t.Fatal(err)
	}
	if capture.mode != "-awg-delete" || capture.policy != platformhelper.Caller {
		t.Fatal("AWG cancellation contract lost")
	}
}
