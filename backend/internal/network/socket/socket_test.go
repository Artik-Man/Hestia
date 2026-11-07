package socket

import (
	"errors"
	"reflect"
	"testing"
)

// TestBindingOptionOrder preserves confinement setup and stops on required device failures.
func TestBindingOptionOrder(t *testing.T) {
	failure := errors.New("denied")
	for _, tc := range []struct {
		name               string
		path               Path
		deviceErr, markErr error
		want               []string
		wantError          bool
	}{
		{"device", Path{Device: "eth0", Mode: DeviceOnly}, nil, nil, []string{"device"}, false},
		{"quality", Path{Device: "eth0", Mode: DeviceThenMark, Mark: 514}, nil, nil, []string{"device", "mark"}, false},
		{"quality zero mark", Path{Device: "eth0", Mode: DeviceThenMark}, nil, nil, []string{"device"}, false},
		{"quality device rejected", Path{Device: "eth0", Mode: DeviceThenMark, Mark: 514}, failure, nil, []string{"device"}, true},
		{"quality mark rejected", Path{Device: "eth0", Mode: DeviceThenMark, Mark: 514}, nil, failure, []string{"device", "mark"}, true},
		{"runtime mark rejected", Path{Device: "awg0", Mode: MarkAndDevice, Mark: 514}, nil, failure, []string{"mark", "device"}, true},
		{"unknown mode", Path{Device: "eth0", Mode: 99}, nil, nil, nil, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls []string
			err := applyOptions(tc.path, func() error { calls = append(calls, "device"); return tc.deviceErr }, func() error { calls = append(calls, "mark"); return tc.markErr })
			if !reflect.DeepEqual(calls, tc.want) || (err != nil) != tc.wantError {
				t.Fatalf("calls %v error %v", calls, err)
			}
		})
	}
}
