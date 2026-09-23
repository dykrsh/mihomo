package neighbor

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

type fakeQuery struct {
	get   func(context.Context, int, netip.Addr) (MAC, bool, error)
	probe func(context.Context, int, netip.Addr) error
	close func()
}

func (q *fakeQuery) Get(ctx context.Context, index int, ip netip.Addr) (MAC, bool, error) {
	return q.get(ctx, index, ip)
}
func (q *fakeQuery) Probe(ctx context.Context, index int, ip netip.Addr) error {
	if q.probe == nil {
		return errors.New("unexpected probe")
	}
	return q.probe(ctx, index, ip)
}
func (q *fakeQuery) Close() error {
	if q.close != nil {
		q.close()
	}
	return nil
}
func emptyLAN(t *testing.T) *table {
	t.Helper()
	tab := newTable()
	for _, e := range []event{{link: true, index: 2, name: "lan", probeable: true}, {address: true, index: 2, prefix: netip.MustParsePrefix("192.0.2.1/24")}, {address: true, index: 2, prefix: netip.MustParsePrefix("2001:db8::1/64")}} {
		if err := tab.apply(e); err != nil {
			t.Fatal(err)
		}
	}
	return tab
}
func recoveryResolver(t *testing.T, opts Options, tab *table, open func() (queryBackend, error)) *Resolver {
	t.Helper()
	b := &fakeBackend{snapshot: tab, batches: make(chan fakeBatch), closed: make(chan struct{})}
	r := New(func(err error) { t.Log(err) })
	r.open = func() (backend, error) { return b, nil }
	r.query = open
	r.Configure(opts)
	r.SetEnabled(true)
	t.Cleanup(func() { r.SetEnabled(false) })
	return r
}
func publish(t *testing.T, r *Resolver, e event) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.table.apply(e); err != nil {
		t.Fatal(err)
	}
	r.notifyLocked()
}

func TestRecoveryPassiveAndKnown(t *testing.T) {
	calls := 0
	r := recoveryResolver(t, Options{Probe: true, Timeout: time.Second}, emptyLAN(t), func() (queryBackend, error) {
		calls++
		return &fakeQuery{get: func(ctx context.Context, index int, ip netip.Addr) (MAC, bool, error) {
			if index != 2 || ip != testIP {
				t.Error("wrong targeted query", index, ip)
			}
			deadline, ok := ctx.Deadline()
			if !ok || time.Until(deadline) > queryTimeout {
				t.Error("missing query budget")
			}
			return testMAC, true, nil
		}}, nil
	})
	if got, ok := r.Resolve(context.Background(), 0, testIP); !ok || got != testMAC {
		t.Fatal("existing kernel entry not resolved")
	}
	if _, ok := r.Lookup(0, testIP); ok {
		t.Fatal("query result was written into notification cache")
	}
	publish(t, r, event{index: 2, ip: testIP, mac: testMAC})
	if _, ok := r.Resolve(context.Background(), 0, testIP); !ok || calls != 1 {
		t.Fatal("cache hit performed recovery")
	}
	r.SetEnabled(false)
	if _, ok := r.Resolve(context.Background(), 0, testIP); ok || calls != 1 {
		t.Fatal("disabled resolver performed recovery")
	}
}
func TestRecoveryProbeOffAndCooldown(t *testing.T) {
	var opens atomic.Int32
	r := recoveryResolver(t, DefaultOptions(), emptyLAN(t), func() (queryBackend, error) {
		opens.Add(1)
		return &fakeQuery{get: func(context.Context, int, netip.Addr) (MAC, bool, error) { return MAC{}, false, nil }}, nil
	})
	done := make(chan bool, 1)
	go func() { _, ok := r.Resolve(context.Background(), 0, testIP); done <- ok }()
	select {
	case ok := <-done:
		if ok {
			t.Fatal("unknown matched")
		}
	case <-time.After(500 * time.Millisecond):
		t.Fatal("probe-off lookup waited for absent neighbor")
	}
	_, _ = r.Resolve(context.Background(), 0, testIP)
	if opens.Load() != 1 {
		t.Fatal("negative cooldown did not suppress repeated queries")
	}
	publish(t, r, event{index: 2, ip: testIP, mac: testMAC})
	if _, ok := r.Resolve(context.Background(), 0, testIP); !ok {
		t.Fatal("cooldown hid fresh notification")
	}
}
func TestRecoveryProbeNotification(t *testing.T) {
	probed := make(chan struct{})
	result := make(chan bool, 1)
	r := recoveryResolver(t, Options{Probe: true, Timeout: time.Second}, emptyLAN(t), func() (queryBackend, error) {
		return &fakeQuery{get: func(context.Context, int, netip.Addr) (MAC, bool, error) { return MAC{}, false, nil }, probe: func(ctx context.Context, index int, ip netip.Addr) error {
			if index != 2 || ip != testIP {
				t.Error("probe selected wrong interface")
			}
			close(probed)
			return nil
		}}, nil
	})
	go func() { mac, ok := r.Resolve(context.Background(), 0, testIP); result <- ok && mac == testMAC }()
	<-probed
	publish(t, r, event{index: 2, ip: testIP, mac: testMAC})
	select {
	case ok := <-result:
		if !ok {
			t.Fatal("probe result not used")
		}
	case <-time.After(time.Second):
		t.Fatal("waiter was not woken by event")
	}
}
func TestRecoveryOneTotalDeadline(t *testing.T) {
	timeout := 80 * time.Millisecond
	started := time.Now()
	var deadlineBeforeProbe time.Time
	r := recoveryResolver(t, Options{Probe: true, Timeout: timeout}, emptyLAN(t), func() (queryBackend, error) {
		return &fakeQuery{get: func(ctx context.Context, _ int, _ netip.Addr) (MAC, bool, error) {
			deadlineBeforeProbe, _ = ctx.Deadline()
			select {
			case <-time.After(25 * time.Millisecond):
				return MAC{}, false, nil
			case <-ctx.Done():
				return MAC{}, false, ctx.Err()
			}
		}, probe: func(ctx context.Context, _ int, _ netip.Addr) error {
			deadline, _ := ctx.Deadline()
			if !deadline.Equal(deadlineBeforeProbe) {
				t.Error("probe reset total deadline")
			}
			return nil
		}}, nil
	})
	if _, ok := r.Resolve(context.Background(), 0, testIP); ok {
		t.Fatal("unknown matched")
	}
	if time.Since(started) > 500*time.Millisecond {
		t.Fatal("total timeout not enforced")
	}
}
func TestRecoverySharedCancellation(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var calls atomic.Int32
	r := recoveryResolver(t, Options{Timeout: time.Second}, emptyLAN(t), func() (queryBackend, error) {
		return &fakeQuery{get: func(ctx context.Context, _ int, _ netip.Addr) (MAC, bool, error) {
			if calls.Add(1) == 1 {
				close(entered)
			}
			select {
			case <-release:
				return testMAC, true, nil
			case <-ctx.Done():
				return MAC{}, false, ctx.Err()
			}
		}}, nil
	})
	first, cancel := context.WithCancel(context.Background())
	defer cancel()
	a, b := make(chan bool, 1), make(chan bool, 1)
	go func() { _, ok := r.Resolve(first, 0, testIP); a <- ok }()
	<-entered
	go func() { _, ok := r.Resolve(context.Background(), 0, testIP); b <- ok }()
	eventually(t, func() bool { r.recovery.mu.Lock(); defer r.recovery.mu.Unlock(); return r.recovery.waiters == 2 })
	cancel()
	if <-a {
		t.Fatal("cancelled waiter succeeded")
	}
	close(release)
	if !<-b {
		t.Fatal("one waiter cancelled another")
	}
	if calls.Load() != 1 {
		t.Fatal("duplicate recovery for same source")
	}
}
func TestRecoveryShutdownAndReconfigure(t *testing.T) {
	for _, configure := range []bool{false, true} {
		t.Run(map[bool]string{false: "shutdown", true: "disable-probe"}[configure], func(t *testing.T) {
			entered, closed := make(chan struct{}), make(chan struct{})
			r := recoveryResolver(t, Options{Probe: true, Timeout: time.Second}, emptyLAN(t), func() (queryBackend, error) {
				return &fakeQuery{
					get: func(ctx context.Context, _ int, _ netip.Addr) (MAC, bool, error) {
						close(entered)
						<-ctx.Done()
						return MAC{}, false, ctx.Err()
					}, close: func() { close(closed) },
				}, nil
			})
			result := make(chan bool, 1)
			go func() { _, ok := r.Resolve(context.Background(), 0, testIP); result <- ok }()
			<-entered
			if configure {
				r.Configure(DefaultOptions())
			} else {
				r.SetEnabled(false)
			}
			if <-result {
				t.Fatal("cancelled recovery succeeded")
			}
			select {
			case <-closed:
			default:
				t.Fatal("query socket outlived shutdown/reconfiguration")
			}
		})
	}
}
func TestRecoveryRejectsAmbiguousQueryAndStaleReply(t *testing.T) {
	for _, mode := range []string{"ambiguous", "changed", "too-many-interfaces"} {
		t.Run(mode, func(t *testing.T) {
			tab := emptyLAN(t)
			if mode != "changed" {
				tab.apply(event{link: true, index: 3, name: "guest"})
			}
			if mode == "too-many-interfaces" {
				for i := 4; i < maxQueryInterfaces+4; i++ {
					tab.apply(event{link: true, index: i, name: "extra"})
				}
			}
			calls := 0
			var r *Resolver
			r = recoveryResolver(t, Options{Probe: true, Timeout: time.Second}, tab, func() (queryBackend, error) {
				return &fakeQuery{get: func(context.Context, int, netip.Addr) (MAC, bool, error) {
					calls++
					if mode == "changed" {
						r.mu.Lock()
						r.notifyLocked()
						r.mu.Unlock()
					}
					return testMAC, true, nil
				}}, nil
			})
			if _, ok := r.Resolve(context.Background(), 0, testIP); ok {
				t.Fatal("ambiguous/stale reply used")
			}
			if mode == "too-many-interfaces" && calls != 0 {
				t.Fatal("unbounded interface queries")
			}
		})
	}
}
func TestProbeScope(t *testing.T) {
	tab := emptyLAN(t)
	for _, ip := range []string{"192.0.2.10", "2001:db8::1234"} {
		if got := tab.probeInterface(recoveryKey{ip: netip.MustParseAddr(ip)}); got != 2 {
			t.Fatal("missing on-link scope", ip, got)
		}
	}
	for _, ip := range []string{"198.51.100.10", "192.0.2.1", "192.0.2.0", "192.0.2.255", "2001:db8::1"} {
		if got := tab.probeInterface(recoveryKey{ip: netip.MustParseAddr(ip)}); got != 0 {
			t.Fatal("unsafe probe scope", ip, got)
		}
	}
	tab.apply(event{link: true, index: 3, name: "guest", probeable: true})
	tab.apply(event{address: true, index: 3, prefix: netip.MustParsePrefix("192.0.2.2/24")})
	if tab.probeInterface(recoveryKey{ip: testIP}) != 0 {
		t.Fatal("overlapping networks should not guess interface")
	}
	if tab.probeInterface(recoveryKey{index: 2, ip: testIP}) != 2 {
		t.Fatal("explicit scope ignored")
	}
	tab.apply(event{link: true, index: 2, name: "lan", probeable: false})
	if tab.probeInterface(recoveryKey{index: 2, ip: testIP}) != 0 {
		t.Fatal("down/non-Ethernet interface probed")
	}
}
func TestRecoveryAdmissionLimits(t *testing.T) {
	r := recoveryResolver(t, Options{Timeout: time.Second}, emptyLAN(t), func() (queryBackend, error) {
		return &fakeQuery{get: func(ctx context.Context, _ int, _ netip.Addr) (MAC, bool, error) {
			<-ctx.Done()
			return MAC{}, false, ctx.Err()
		}}, nil
	})
	results := make(chan bool, maxRecoveries)
	for i := 0; i < maxRecoveries; i++ {
		ip := testIP
		for j := 0; j < i; j++ {
			ip = ip.Next()
		}
		go func(ip netip.Addr) { _, ok := r.Resolve(context.Background(), 0, ip); results <- ok }(ip)
	}
	eventually(t, func() bool {
		r.recovery.mu.Lock()
		defer r.recovery.mu.Unlock()
		return len(r.recovery.flights) == maxRecoveries
	})
	if _, ok := r.Resolve(context.Background(), 0, netip.MustParseAddr("192.0.2.100")); ok {
		t.Fatal("capacity overflow matched")
	}
	r.SetEnabled(false)
	for i := 0; i < maxRecoveries; i++ {
		if <-results {
			t.Fatal("cancelled query matched")
		}
	}
}

func TestRecoveryPassiveBudgetAndLastWaiterCancellation(t *testing.T) {
	for _, cancelWaiter := range []bool{false, true} {
		t.Run(map[bool]string{false: "passive-timeout", true: "last-waiter-cancels"}[cancelWaiter], func(t *testing.T) {
			entered, closed := make(chan struct{}), make(chan struct{})
			r := recoveryResolver(t, Options{Probe: true, Timeout: time.Second}, emptyLAN(t), func() (queryBackend, error) {
				return &fakeQuery{get: func(ctx context.Context, _ int, _ netip.Addr) (MAC, bool, error) {
					close(entered)
					<-ctx.Done()
					return MAC{}, false, ctx.Err()
				}, close: func() { close(closed) }}, nil
			})
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			result := make(chan bool, 1)
			go func() { _, ok := r.Resolve(ctx, 0, testIP); result <- ok }()
			<-entered
			if cancelWaiter {
				cancel()
			}
			select {
			case ok := <-result:
				if ok {
					t.Fatal("cancelled/timed-out query matched")
				}
			case <-time.After(500 * time.Millisecond):
				t.Fatal("passive query waited for total probe budget")
			}
			select {
			case <-closed:
			case <-time.After(500 * time.Millisecond):
				t.Fatal("query socket not released")
			}
		})
	}
}
