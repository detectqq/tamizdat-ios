package tamizdat

import "sync"

type shortIDPool struct {
	master      [8]byte
	current     map[[8]byte]struct{}
	previous    []map[[8]byte]struct{}
	maxPrevious int
	mu          sync.RWMutex
}

func newShortIDPool(master [8]byte, graceWindow int) *shortIDPool {
	if graceWindow < 0 {
		graceWindow = 0
	}
	return &shortIDPool{
		master:      master,
		current:     make(map[[8]byte]struct{}),
		maxPrevious: graceWindow,
	}
}

func (p *shortIDPool) Accept(short [8]byte) bool {
	if p == nil {
		return false
	}
	p.mu.RLock()
	defer p.mu.RUnlock()
	if short == p.master {
		return true
	}
	if _, ok := p.current[short]; ok {
		return true
	}
	for _, prev := range p.previous {
		if _, ok := prev[short]; ok {
			return true
		}
	}
	return false
}

func (p *shortIDPool) Rotate(newEpochKey string, size int) {
	if p == nil {
		return
	}
	derived := DeriveShortIDPool(p.master, newEpochKey, size)
	current := make(map[[8]byte]struct{}, len(derived))
	for _, id := range derived {
		current[id] = struct{}{}
	}

	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.current) > 0 && p.maxPrevious > 0 {
		p.previous = append(p.previous, p.current)
		if len(p.previous) > p.maxPrevious {
			copy(p.previous, p.previous[len(p.previous)-p.maxPrevious:])
			p.previous = p.previous[:p.maxPrevious]
		}
	}
	p.current = current
}
