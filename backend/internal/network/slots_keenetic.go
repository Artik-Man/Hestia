//go:build keenetic

package network

// SlotCount fits four AWG pairs into the free Keenetic rule priorities before its default main lookup at priority 9.
const SlotCount = 4

// MarkRulePriority assigns one priority below Keenetic's priority 9 main lookup to an AWG slot.
func MarkRulePriority(slot int) int { return 1 + 2*slot }

// OuterRulePriority assigns the adjacent blackhole priority to the same AWG slot.
func OuterRulePriority(slot int) int { return 2 + 2*slot }
