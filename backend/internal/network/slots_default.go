//go:build !keenetic

package network

// SlotCount bounds Linux tunnel allocation below its reserved routing resources.
const SlotCount = 50

// MarkRulePriority reserves a stable policy priority for a Linux AWG slot.
func MarkRulePriority(slot int) int { return 1002 + slot }

// OuterRulePriority reserves a stable terminal guard priority for a Linux AWG slot.
func OuterRulePriority(slot int) int { return 1100 + slot }
