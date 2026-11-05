package quality

import "time"

// A fixed-size linked block avoids reallocating a day's observations under peak load.
// Each sample occupies one 64-bit word: monotonic nanoseconds since the first sample in its block and five outcome bits, including the classic DNS error code.
type sampleBlock struct {
	base       time.Duration
	values     [64]int64
	start, end int
	next       *sampleBlock
}

type windowSeries struct {
	head, tail *sampleBlock
	counts     [18]int
}

// add records one observation in completion order and updates its outcome counter.
func (s *windowSeries) add(elapsed time.Duration, result outcome) {
	if s.tail == nil || s.tail.end == len(s.tail.values) || elapsed-s.tail.base > 24*time.Hour {
		block := &sampleBlock{base: elapsed}
		if s.tail == nil {
			s.head = block
		} else {
			s.tail.next = block
		}
		s.tail = block
	}
	s.tail.values[s.tail.end] = int64(elapsed-s.tail.base)<<5 | int64(result)
	s.tail.end++
	s.counts[result]++
}

// expire consumes only samples older than the inclusive cutoff and frees exhausted blocks.
func (s *windowSeries) expire(cutoff time.Duration) {
	for s.head != nil {
		block := s.head
		for block.start < block.end {
			word := block.values[block.start]
			if block.base+time.Duration(word>>5) >= cutoff {
				return
			}
			s.counts[word&31]--
			block.start++
		}
		s.head = block.next
	}
	s.tail = nil
}

// record appends the sample to its series while the caller holds the engine lock.
func (e *Engine) record(key seriesKey, at time.Time, result outcome) {
	series := e.history[key]
	if series == nil {
		series = &windowSeries{}
		e.history[key] = series
	}
	series.add(at.Sub(e.started), result)
}

// expire advances every running counter to the same instant and retires abandoned empty series.
func (e *Engine) expire(at time.Time) {
	cutoff := at.Sub(e.started) - time.Duration(e.settings.WindowMinutes)*time.Minute
	for k, s := range e.history {
		s.expire(cutoff)
		if s.head == nil {
			delete(e.history, k)
		}
	}
}
