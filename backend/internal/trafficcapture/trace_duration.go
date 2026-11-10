package trafficcapture

import "time"

// boundedTraceDuration excludes post-window cleanup time from the persisted session duration.
func boundedTraceDuration(elapsed time.Duration, requestedSeconds int) int {
	limit := requestedSeconds * int(time.Second/time.Millisecond)
	measured := int(elapsed.Milliseconds())
	if measured > limit {
		return limit
	}
	if measured < 0 {
		return 0
	}
	return measured
}
