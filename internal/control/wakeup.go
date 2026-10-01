package control

import "sync"

// Wakeup 只缩短本进程任务投递等待；持久任务和跨副本恢复仍以 PostgreSQL 为准。
type Wakeup struct {
	mu        sync.Mutex
	listeners map[string]map[chan struct{}]struct{}
}

func (w *Wakeup) Watch(tenant, sensor string) (<-chan struct{}, func()) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.listeners == nil {
		w.listeners = make(map[string]map[chan struct{}]struct{})
	}
	key := tenant + "/" + sensor
	if w.listeners[key] == nil {
		w.listeners[key] = make(map[chan struct{}]struct{})
	}
	c := make(chan struct{}, 1)
	w.listeners[key][c] = struct{}{}
	return c, func() {
		w.mu.Lock()
		defer w.mu.Unlock()
		delete(w.listeners[key], c)
		if len(w.listeners[key]) == 0 {
			delete(w.listeners, key)
		}
	}
}
func (w *Wakeup) Notify(tenant, sensor string) {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	for c := range w.listeners[tenant+"/"+sensor] {
		select {
		case c <- struct{}{}:
		default:
		}
	}
}
