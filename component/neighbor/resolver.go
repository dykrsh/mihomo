// Package neighbor resolves directly connected source addresses from a
// snapshot kept current by kernel notifications.
package neighbor

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

const (
	maxEntries      = 65536
	maxLinks        = 4096
	snapshotTimeout = 5 * time.Second
)

var ErrUnsupported = errors.New("source MAC lookup is not supported on this platform")
var errCapacity = errors.New("neighbor table capacity exceeded")
var errUnknownInterface = errors.New("neighbor refers to an unknown interface")

type MAC [6]byte

func (m MAC) String() string { return net.HardwareAddr(m[:]).String() }

type event struct {
	index  int
	ip     netip.Addr
	mac    MAC
	name   string
	link   bool
	remove bool
}

type table struct {
	byIP  map[netip.Addr]map[int]MAC
	links map[int]string
	names map[string]int
	count int
}

func newTable() *table {
	return &table{byIP: make(map[netip.Addr]map[int]MAC), links: make(map[int]string), names: make(map[string]int)}
}

func (t *table) apply(e event) error {
	if e.link {
		if old, ok := t.links[e.index]; ok {
			delete(t.names, old)
		}
		if e.remove {
			delete(t.links, e.index)
			for ip, entries := range t.byIP {
				if _, ok := entries[e.index]; ok {
					delete(entries, e.index)
					t.count--
				}
				if len(entries) == 0 {
					delete(t.byIP, ip)
				}
			}
			return nil
		}
		if _, exists := t.links[e.index]; !exists && len(t.links) >= maxLinks {
			return errCapacity
		}
		t.links[e.index] = e.name
		t.names[e.name] = e.index
		return nil
	}
	entries := t.byIP[e.ip]
	if e.remove {
		if _, ok := entries[e.index]; ok {
			delete(entries, e.index)
			t.count--
			if len(entries) == 0 {
				delete(t.byIP, e.ip)
			}
		}
		return nil
	}
	if _, ok := t.links[e.index]; !ok {
		// Ignoring this entry could make an address on another interface
		// appear unique. Invalidate and resync instead of guessing its scope.
		return errUnknownInterface
	}
	if _, ok := entries[e.index]; !ok {
		if t.count >= maxEntries {
			return errCapacity
		}
		t.count++
	}
	if entries == nil {
		entries = make(map[int]MAC)
		t.byIP[e.ip] = entries
	}
	entries[e.index] = e.mac
	return nil
}

func (t *table) lookup(index int, ip netip.Addr) (MAC, bool) {
	if !ip.IsValid() || ip.IsUnspecified() || ip.IsMulticast() || ip.IsLoopback() {
		return MAC{}, false
	}
	if zone := ip.Zone(); zone != "" {
		zoneIndex, err := strconv.Atoi(zone)
		if err != nil {
			zoneIndex = t.names[zone]
		}
		if zoneIndex <= 0 || (index != 0 && index != zoneIndex) {
			return MAC{}, false
		}
		index = zoneIndex
		ip = ip.WithZone("")
	}
	entries := t.byIP[ip.Unmap()]
	if index != 0 {
		mac, ok := entries[index]
		return mac, ok
	}
	if len(entries) == 1 {
		for _, mac := range entries {
			return mac, true
		}
	}
	return MAC{}, false
}

type backend interface {
	Snapshot(context.Context) (*table, error)
	Next(context.Context) ([]event, error)
	Close() error
}

// Resolver owns one subscription shared by all rules. Its lifecycle must be
// managed by the applied configuration, never by rule construction or Match.
type Resolver struct {
	lifecycle sync.Mutex
	cancel    context.CancelFunc
	done      chan struct{}
	mu        sync.RWMutex
	table     *table // nil until a complete, consistent snapshot is available
	open      func() (backend, error)
	report    func(error)
}

func New(report func(error)) *Resolver {
	return &Resolver{open: openBackend, report: report}
}

// SetEnabled waits for the first bounded initialization attempt, or for the old
// subscription to stop. Lookup never waits for initialization.
func (r *Resolver) SetEnabled(enabled bool) {
	r.lifecycle.Lock()
	defer r.lifecycle.Unlock()
	if !enabled {
		if r.cancel != nil {
			r.cancel()
			<-r.done
			r.cancel = nil
		}
		r.replace(nil)
		return
	}
	if r.cancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.cancel = cancel
	r.done = make(chan struct{})
	ready := make(chan struct{})
	go r.run(ctx, ready)
	<-ready
}

func (r *Resolver) Lookup(index int, ip netip.Addr) (MAC, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.table == nil {
		return MAC{}, false
	}
	return r.table.lookup(index, ip)
}

func (r *Resolver) replace(t *table) {
	r.mu.Lock()
	r.table = t
	r.mu.Unlock()
}

func (r *Resolver) session(ctx context.Context, ready func()) error {
	b, err := r.open()
	if err != nil {
		return err
	}
	defer b.Close()
	initCtx, cancel := context.WithTimeout(ctx, snapshotTimeout)
	t, err := b.Snapshot(initCtx)
	cancel()
	if err != nil {
		return err
	}
	r.replace(t)
	ready()
	for {
		events, err := b.Next(ctx)
		if err != nil {
			return err
		}
		r.mu.Lock()
		for _, e := range events {
			if err = t.apply(e); err != nil {
				break
			}
		}
		if err != nil {
			r.table = nil
		}
		r.mu.Unlock()
		if err != nil {
			return err
		}
	}
}

func (r *Resolver) run(ctx context.Context, initialized chan struct{}) {
	defer close(r.done)
	defer r.replace(nil)
	var once sync.Once
	ready := func() { once.Do(func() { close(initialized) }) }
	defer ready()
	backoff := time.Second
	var lastReport time.Time
	for {
		started := time.Now()
		err := r.session(ctx, ready)
		r.replace(nil)
		ready()
		if ctx.Err() != nil {
			return
		}
		if r.report != nil && time.Since(lastReport) >= 30*time.Second {
			r.report(err)
			lastReport = time.Now()
		}
		if errors.Is(err, ErrUnsupported) {
			return
		}
		if time.Since(started) >= time.Minute {
			backoff = time.Second
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
		if backoff < 30*time.Second {
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
		}
	}
}
