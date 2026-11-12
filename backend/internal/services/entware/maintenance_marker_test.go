package entware

import "testing"

// TestParsePackageMaintenanceMarker accepts only the canonical transaction marker and rejects malformed bytes.
func TestParsePackageMaintenanceMarker(t *testing.T) {
	validMarker := []byte("123 01234567-89ab-cdef-0123-456789abcdef 456\n")
	tests := []struct {
		name  string
		data  []byte
		valid bool
	}{
		{name: "canonical marker", data: validMarker, valid: true},
		{name: "empty marker", data: nil},
		{name: "missing final newline", data: []byte("123 01234567-89ab-cdef-0123-456789abcdef 456")},
		{name: "second line", data: []byte("123 01234567-89ab-cdef-0123-456789abcdef 456\n\n")},
		{name: "unterminated suffix", data: []byte("123 01234567-89ab-cdef-0123-456789abcdef 456\nJUNK")},
		{name: "NUL suffix", data: []byte("123 01234567-89ab-cdef-0123-456789abcdef 456\n\x00")},
		{name: "tab delimiter", data: []byte("123\t01234567-89ab-cdef-0123-456789abcdef 456\n")},
		{name: "repeated spaces", data: []byte("123  01234567-89ab-cdef-0123-456789abcdef 456\n")},
		{name: "signed PID", data: []byte("+123 01234567-89ab-cdef-0123-456789abcdef 456\n")},
		{name: "signed start time", data: []byte("123 01234567-89ab-cdef-0123-456789abcdef +456\n")},
		{name: "leading zero PID", data: []byte("0123 01234567-89ab-cdef-0123-456789abcdef 456\n")},
		{name: "leading zero start time", data: []byte("123 01234567-89ab-cdef-0123-456789abcdef 0456\n")},
		{name: "reserved PID", data: []byte("1 01234567-89ab-cdef-0123-456789abcdef 456\n")},
		{name: "zero start time", data: []byte("123 01234567-89ab-cdef-0123-456789abcdef 0\n")},
		{name: "extra field", data: []byte("123 01234567-89ab-cdef-0123-456789abcdef 456 extra\n")},
		{name: "too large", data: make([]byte, 129)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			marker, valid := parsePackageMaintenanceMarker(test.data)
			if valid != test.valid {
				t.Fatalf("valid = %t, want %t", valid, test.valid)
			}
			if !valid {
				return
			}
			want := packageMaintenanceMarker{
				pid:       123,
				bootID:    "01234567-89ab-cdef-0123-456789abcdef",
				startTime: 456,
			}
			if marker != want {
				t.Fatalf("marker = %#v, want %#v", marker, want)
			}
		})
	}
}
