//go:build linux && keenetic

package keeneticroute

import (
	"reflect"
	"strconv"
	"testing"

	"github.com/Artik-Man/Hestia/internal/network"
)

// TestKeeneticCommandArgsTranslatesOuterBarrier checks Linux's outer guard command is represented by Keenetic's blackhole rule form.
func TestKeeneticCommandArgsTranslatesOuterBarrier(t *testing.T) {
	for _, operation := range []string{"add", "del"} {
		input := []string{"-4", "rule", operation, "priority", "2", "fwmark", "0x51000/0xffffffff", "unreachable"}
		want := []string{"-4", "rule", operation, "priority", "2", "fwmark", "0x51000/0xffffffff", "lookup", "unspec", "type", "blackhole"}
		input[4] = strconv.Itoa(network.OuterRulePriority(0))
		want[4] = input[4]
		if !validRouteCommand(input) {
			t.Fatalf("validRouteCommand(%v) = false", input)
		}
		if got := keeneticCommandArgs(input); !reflect.DeepEqual(got, want) {
			t.Fatalf("keeneticCommandArgs(%v) = %v, want %v", input, got, want)
		}
	}
}
