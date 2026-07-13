package anytls

import "sync/atomic"

func (lw *ListenerWrapper) acquire() bool {
	if lw.MaxConcurrent <= 0 {
		return true
	}

	for {
		current := atomic.LoadInt64(&lw.active)
		if int(current) >= lw.MaxConcurrent {
			return false
		}
		if atomic.CompareAndSwapInt64(&lw.active, current, current+1) {
			return true
		}
	}
}

func (lw *ListenerWrapper) release() {
	if lw.MaxConcurrent <= 0 {
		return
	}
	atomic.AddInt64(&lw.active, -1)
}

func (lw *ListenerWrapper) acquireStream(connectionID uint64) bool {
	if !lw.acquireSessionStream(connectionID) {
		return false
	}
	if !acquireCounter(&lw.activeStreams, lw.MaxConcurrentStreams) {
		lw.releaseSessionStream(connectionID)
		return false
	}
	return true
}

func (lw *ListenerWrapper) releaseStream(connectionID uint64) {
	if lw.MaxConcurrentStreams > 0 {
		atomic.AddInt64(&lw.activeStreams, -1)
	}
	lw.releaseSessionStream(connectionID)
}

func acquireCounter(counter *int64, limit int) bool {
	if limit <= 0 {
		return true
	}
	for {
		current := atomic.LoadInt64(counter)
		if int(current) >= limit {
			return false
		}
		if atomic.CompareAndSwapInt64(counter, current, current+1) {
			return true
		}
	}
}
