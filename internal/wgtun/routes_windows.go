//go:build wgtun

package wgtun

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/aethergui/aethergui/internal/config"
	"github.com/aethergui/aethergui/internal/logx"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

// routeManager installs and reverts the routing/DNS a native WireGuard tunnel
// needs on Windows:
//
//  1. lower the wintun adapter's interface metric so its default route wins;
//  2. a host route for the WireGuard endpoint on the *physical* link - without
//     it the handshake packets would be routed back into their own tunnel,
//     which is an instant loop and no traffic ever flows;
//  3. a default route (0.0.0.0/0 and ::/0) through the wintun adapter;
//  4. the tunnel DNS on the adapter's registry key (1.1.1.1 / 1.0.0.1).
//
// Revert deletes exactly the routes it added and restores the prior DNS.
type routeManager struct {
	luid uint64
	dns  []string

	// DNS restore bookkeeping.
	dnsPath    string
	oldDNS     string
	haveOldDNS bool

	// Interface-metric restore bookkeeping: the per-family metric and
	// UseAutomaticMetric read before lowering them, so Revert can put them
	// back. Index 0 = IPv4, 1 = IPv6.
	ifMetric [2]ifMetricState

	added []windows.MibIpForwardRow2
}

// ifMetricState remembers an adapter's per-family metric before we lowered it.
type ifMetricState struct {
	have   bool
	metric uint32
	auto   uint8
}

// newRouteManager captures the adapter LUID and the DNS servers to install.
func newRouteManager(luid uint64, dns []string) *routeManager {
	return &routeManager{luid: luid, dns: dns}
}

// ApplyEndpointRoute performs the pre-handshake steps: it persists the
// pre-change state, lowers the wintun interface metric, and installs the
// endpoint host route on the *physical* link. None of these flip the default
// route, so handshake packets keep a real path. Call right after Up(); wait for
// the handshake; then ApplyDefaultRoutes, then ApplyDNS.
func (m *routeManager) ApplyEndpointRoute(endpoint string) error {
	epIP, epFamily, err := parseEndpointIP(endpoint)
	if err != nil {
		return err
	}

	// Physical default route, captured before any change. Also proves the
	// family actually has connectivity to pin the endpoint onto.
	phys, err := defaultRoute(epFamily)
	if err != nil {
		return fmt.Errorf("wgtun: no %s default route to pin the endpoint on: %w", familyName(epFamily), err)
	}

	// Persist the pre-change state (metric/DNS/LUID) BEFORE the first system
	// mutation, so an unclean exit can be recovered on next start.
	if err := m.writeState(); err != nil {
		logx.Warnf("[wgtun] state: write failed: %v", err)
	}

	// Make the wintun interface win the default-route election later. The
	// effective route metric is interface metric + route metric, so a metric-0
	// route on a metric-25 interface still loses - the interface itself must
	// drop too.
	if err := m.setInterfaceMetric(1); err != nil {
		m.restoreInterfaceMetric()
		return fmt.Errorf("wgtun: lowering wintun metric: %w", err)
	}

	// Endpoint host route FIRST, on the physical link, so the handshake keeps
	// a real path once the default route flips.
	epLen := uint8(32)
	if epFamily == windows.AF_INET6 {
		epLen = 128
	}
	if err := m.add(makeRoute(epSockaddr(epIP, epFamily), epLen, phys.NextHop, phys.InterfaceLuid, 0)); err != nil {
		if rerr := m.Revert(); rerr != nil {
			logx.Errorf("[wgtun] revert during apply rollback: %v", rerr)
		}
		return err
	}
	return nil
}

// applyHostRouteOnly installs the endpoint host route on the physical link
// WITHOUT lowering the interface metric. Used for the OUTER layer of a stacked
// tunnel, which must NOT install a default route or lower its metric — its only
// job is to carry the inner endpoint via an explicit /32 route, so its metric
// must stay untouched (the inner layer's metric=1 default route is the only one
// that wins).
func (m *routeManager) applyHostRouteOnly(endpoint string) error {
	epIP, epFamily, err := parseEndpointIP(endpoint)
	if err != nil {
		return err
	}
	phys, err := defaultRoute(epFamily)
	if err != nil {
		return fmt.Errorf("wgtun: no %s default route to pin the endpoint on: %w", familyName(epFamily), err)
	}
	if err := m.writeState(); err != nil {
		logx.Warnf("[wgtun] state: write failed: %v", err)
	}
	epLen := uint8(32)
	if epFamily == windows.AF_INET6 {
		epLen = 128
	}
	if err := m.add(makeRoute(epSockaddr(epIP, epFamily), epLen, phys.NextHop, phys.InterfaceLuid, 0)); err != nil {
		if rerr := m.Revert(); rerr != nil {
			logx.Errorf("[wgtun] revert during apply rollback: %v", rerr)
		}
		return err
	}
	return nil
}

// ApplyDefaultRoutes flips the default route into the tunnel. It MUST only be
// called after the handshake has succeeded: before that, traffic would be
// black-holed into a tunnel that cannot carry it yet.
func (m *routeManager) ApplyDefaultRoutes() error {
	if err := m.add(makeRoute(sockaddrInet4(net.IPv4zero), 0, sockaddrInet4(net.IPv4zero), m.luid, 0)); err != nil {
		if rerr := m.Revert(); rerr != nil {
			logx.Errorf("[wgtun] revert during apply rollback: %v", rerr)
		}
		return err
	}
	// IPv6 is best-effort: a missing or black-holed ::/0 must never abort an
	// already-up IPv4 tunnel, so a failure here is only logged.
	if _, err := defaultRoute(windows.AF_INET6); err == nil {
		if err := m.add(makeRoute(sockaddrInet6(net.IPv6zero), 0, sockaddrInet6(net.IPv6zero), m.luid, 0)); err != nil {
			logx.Warnf("[wgtun] IPv6 default route skipped: %v", err)
		}
	}
	return nil
}

// ApplyDNS sets the tunnel DNS. Call after the default route is live.
func (m *routeManager) ApplyDNS() error {
	if err := m.applyDNS(); err != nil {
		if rerr := m.Revert(); rerr != nil {
			logx.Errorf("[wgtun] revert during apply rollback: %v", rerr)
		}
		return fmt.Errorf("wgtun: setting DNS: %w", err)
	}
	return nil
}

// add creates one route and records it for Revert. The caller decides whether
// a failure is fatal (and rolls back) or optional (and is merely logged).
func (m *routeManager) add(r windows.MibIpForwardRow2) error {
	if err := createIpForwardEntry2(&r); err != nil {
		// A leftover identical route from a crashed prior run is the goal
		// state already reached — proceed to record it like a fresh add.
		if !isAlreadyExists(err) {
			return fmt.Errorf("wgtun: adding route: %w", err)
		}
		logx.Infof("[wgtun] route already exists; adopting it")
	}
	m.added = append(m.added, r)
	if err := m.recordRoute(r); err != nil {
		logx.Warnf("[wgtun] state: record route failed: %v", err)
	}
	return nil
}

// Revert removes the added routes, restores the previous interface metric and
// DNS. Every sub-step runs even when an earlier one fails, each failure is
// collected and logged, and the aggregated result is returned. Per-step state
// (m.added, m.ifMetric, DNS bookkeeping) is cleared only when that step
// succeeded, so a second Revert retries whatever failed — which makes Revert
// idempotent: once everything is cleared, calling it again is a no-op.
//
// The interface metric MUST be restored explicitly: closing the tunnel only
// closes the wintun handle (WintunCloseAdapter); wintun is an on-demand pool
// and does NOT delete the adapter, so a lowered metric would otherwise stay
// pinned on the reused adapter (and on the registry Interfaces\{GUID} key).
func (m *routeManager) Revert() error {
	var errs []error
	if err := m.revertRoutes(); err != nil {
		errs = append(errs, err)
	}
	if err := m.restoreInterfaceMetric(); err != nil {
		errs = append(errs, err)
	}
	if err := m.revertDNS(); err != nil {
		errs = append(errs, err)
	}
	if len(errs) > 0 {
		joined := errors.Join(errs...)
		logx.Errorf("[wgtun] revert partial failure: %v", joined)
		return joined
	}
	// Fully reverted: the crash-recovery state file is no longer needed.
	if err := clearState(); err != nil {
		logx.Warnf("[wgtun] state: clear failed: %v", err)
	}
	logx.Infof("[wgtun] revert complete")
	return nil
}

// revertDeleteRoute / revertSetMetric are the syscall entry points Revert uses.
// They are package-level variables so tests can substitute mocks and exercise
// Revert offline (partial failure, idempotency) without touching real state.
var (
	revertDeleteRoute = deleteIpForwardEntry2
	revertSetMetric   = setIpInterfaceEntry
)

func (m *routeManager) revertRoutes() error {
	if len(m.added) == 0 {
		return nil
	}
	logx.Infof("[wgtun] revert: routes begin (%d)", len(m.added))
	var errs []error
	kept := make([]windows.MibIpForwardRow2, 0, len(m.added))
	for _, r := range m.added {
		if err := revertDeleteRoute(&r); err != nil {
			// The route already being gone means the goal state is reached; do
			// not keep retrying it forever.
			if isNotFound(err) {
				logx.Infof("[wgtun] revert: route already absent; cleared")
				continue
			}
			logx.Warnf("[wgtun] revert: delete route failed: %v", err)
			errs = append(errs, fmt.Errorf("delete route: %w", err))
			kept = append(kept, r)
			continue
		}
		logx.Infof("[wgtun] revert: route deleted")
	}
	m.added = kept
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	logx.Infof("[wgtun] revert: routes done")
	return nil
}

// applyDNS sets the adapter's DNS via its registry NameServer value. This is
// the registry approach (not SetInterfaceDnsSettings): the prior value is
// stashed so Revert can restore it byte-for-byte. The wintun adapter's
// NameServer becomes a candidate for global resolution while it holds the
// default route.
func (m *routeManager) applyDNS() error {
	guid, err := convertInterfaceLuidToGuid(m.luid)
	if err != nil {
		return err
	}
	m.dnsPath = `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\` + guidString(guid)

	// CreateKey opens-or-creates: a freshly created wintun adapter may not have
	// its Tcpip\Interfaces\<guid> key yet, so OpenKey would return ErrNotExist
	// and abort the whole Apply.
	k, _, err := registry.CreateKey(registry.LOCAL_MACHINE, m.dnsPath, registry.QUERY_VALUE|registry.SET_VALUE)
	if err != nil {
		return err
	}
	defer k.Close()

	if old, _, err := k.GetStringValue("NameServer"); err == nil {
		m.oldDNS = old
		m.haveOldDNS = true
	} else if err != registry.ErrNotExist {
		return err
	}
	if err := k.SetStringValue("NameServer", strings.Join(m.dns, ",")); err != nil {
		return err
	}
	// Flush the resolver cache so the new DNS takes effect immediately instead
	// of on the cache TTL.
	if !flushResolverCache() {
		logx.Warnf("[wgtun] DnsFlushResolverCache failed; DNS may take a moment to apply")
	}
	return nil
}

func (m *routeManager) revertDNS() error {
	if m.dnsPath == "" {
		return nil
	}
	logx.Infof("[wgtun] revert: DNS begin (%s)", m.dnsPath)
	k, err := registry.OpenKey(registry.LOCAL_MACHINE, m.dnsPath, registry.SET_VALUE)
	if err != nil {
		logx.Warnf("[wgtun] revert: DNS open key failed: %v", err)
		return fmt.Errorf("open DNS key: %w", err)
	}
	defer k.Close()
	if m.haveOldDNS {
		if err := k.SetStringValue("NameServer", m.oldDNS); err != nil {
			logx.Warnf("[wgtun] revert: DNS restore failed: %v", err)
			return fmt.Errorf("restore DNS: %w", err)
		}
	} else {
		if err := k.DeleteValue("NameServer"); err != nil {
			logx.Warnf("[wgtun] revert: DNS delete failed: %v", err)
			return fmt.Errorf("delete DNS: %w", err)
		}
	}
	// Success: drop the bookkeeping so a second Revert does not rewrite DNS.
	m.dnsPath = ""
	m.oldDNS = ""
	m.haveOldDNS = false
	logx.Infof("[wgtun] revert: DNS restored")
	return nil
}

// defaultRoute returns the default route (prefix length 0) for a family,
// preferring the lowest EFFECTIVE metric (interface metric + route metric)
// when several 0.0.0.0/0 (or ::/0) entries exist (multiple NICs, a leftover
// VPN, ...). Comparing only route.Metric picks the wrong default on multi-NIC
// machines.
func defaultRoute(family uint16) (windows.MibIpForwardRow2, error) {
	var table *windows.MibIpForwardTable2
	if err := windows.GetIpForwardTable2(family, &table); err != nil {
		return windows.MibIpForwardRow2{}, err
	}
	defer freeMibTable(unsafe.Pointer(table))

	var best windows.MibIpForwardRow2
	bestEff := ^uint32(0)
	found := false
	for _, r := range table.Rows() {
		if r.DestinationPrefix.PrefixLength != 0 || r.DestinationPrefix.Prefix.Family != family {
			continue
		}
		eff := r.Metric
		if ifm, ok := interfaceMetric(r.InterfaceLuid, family); ok {
			eff += ifm
		}
		if !found || eff < bestEff {
			best = r
			bestEff = eff
			found = true
		}
	}
	if !found {
		return windows.MibIpForwardRow2{}, fmt.Errorf("no default route")
	}
	return best, nil
}

// interfaceMetric reads an adapter's per-family interface metric, the base half
// of a route's effective metric.
func interfaceMetric(luid uint64, family uint16) (uint32, bool) {
	var row windows.MibIpInterfaceRow
	initializeIpInterfaceEntry(&row)
	row.Family = family
	row.InterfaceLuid = luid
	if err := getIpInterfaceEntry(&row); err != nil {
		return 0, false
	}
	return row.Metric, true
}

// setInterfaceMetric lowers the adapter's interface metric for both families
// so its default route wins over the physical NIC. IPv4 is required; IPv6 is
// best-effort (an adapter with no v6 entry is normal).
//
// metric MUST be a concrete small value (1), not 0: on Windows an interface
// metric of 0 means "automatic", not "lowest", so it would not win the
// default-route election.
func (m *routeManager) setInterfaceMetric(metric uint32) error {
	for i, family := range []uint16{windows.AF_INET, windows.AF_INET6} {
		// 1. Read the current value only to stash it for Revert.
		var cur windows.MibIpInterfaceRow
		initializeIpInterfaceEntry(&cur)
		cur.Family = family
		cur.InterfaceLuid = m.luid
		if err := getIpInterfaceEntry(&cur); err != nil {
			if i == 0 {
				return fmt.Errorf("adapter has no IPv4 interface entry: %w", err)
			}
			continue
		}
		m.ifMetric[i] = ifMetricState{have: true, metric: cur.Metric, auto: cur.UseAutomaticMetric}

		// 2. Write the new value from a CLEAN row. SetIpInterfaceEntry expects
		// a freshly InitializeIpInterfaceEntry'd row carrying only the identity
		// and the fields to change - do NOT hand it the Get-returned row.
		var set windows.MibIpInterfaceRow
		initializeIpInterfaceEntry(&set)
		set.Family = family
		set.InterfaceLuid = m.luid
		set.UseAutomaticMetric = 0
		set.Metric = metric
		if err := setIpInterfaceEntry(&set); err != nil {
			if i == 0 {
				return err
			}
			continue
		}
	}
	return nil
}

// restoreInterfaceMetric puts back the per-family metric and UseAutomaticMetric
// read in setInterfaceMetric, so the adapter does not stay pinned at a low
// metric after the tunnel is gone.
func (m *routeManager) restoreInterfaceMetric() error {
	var errs []error
	for i, family := range []uint16{windows.AF_INET, windows.AF_INET6} {
		st := m.ifMetric[i]
		if !st.have {
			continue
		}
		logx.Infof("[wgtun] revert: metric begin family=%d", family)
		// Write the stashed value from a CLEAN row (no Get needed: we already
		// hold the original metric and UseAutomaticMetric).
		var set windows.MibIpInterfaceRow
		initializeIpInterfaceEntry(&set)
		set.Family = family
		set.InterfaceLuid = m.luid
		set.UseAutomaticMetric = st.auto
		set.Metric = st.metric
		if err := revertSetMetric(&set); err != nil {
			logx.Warnf("[wgtun] revert: metric restore failed family=%d: %v", family, err)
			errs = append(errs, fmt.Errorf("restore metric family %d: %w", family, err))
			continue // keep the stash so a later Revert retries this family
		}
		m.ifMetric[i] = ifMetricState{}
		logx.Infof("[wgtun] revert: metric restored family=%d", family)
	}
	if len(errs) > 0 {
		return errors.Join(errs...)
	}
	return nil
}

// makeRoute builds a MibIpForwardRow2. Metric is the route-metric component
// (0 = lowest); the adapter's interface metric is lowered separately by
// setInterfaceMetric. Protocol 3 = MIB_IPPROTO_NETMGMT (a static route).
// Immortal and infinite lifetimes keep the route alive for the adapter's
// lifetime.
func makeRoute(dst windows.RawSockaddrInet, prefixLen uint8, nextHop windows.RawSockaddrInet, luid uint64, metric uint32) windows.MibIpForwardRow2 {
	return windows.MibIpForwardRow2{
		InterfaceLuid: luid,
		DestinationPrefix: windows.IpAddressPrefix{
			Prefix:       dst,
			PrefixLength: prefixLen,
		},
		NextHop:           nextHop,
		Metric:            metric,
		Protocol:          3, // MIB_IPPROTO_NETMGMT
		ValidLifetime:     0xFFFFFFFF,
		PreferredLifetime: 0xFFFFFFFF,
		Immortal:          1,
	}
}

func parseEndpointIP(endpoint string) (net.IP, uint16, error) {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		return nil, 0, fmt.Errorf("bad endpoint %q: %w", endpoint, err)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		return nil, 0, fmt.Errorf("bad endpoint host %q", host)
	}
	if v4 := ip.To4(); v4 != nil {
		return v4, windows.AF_INET, nil
	}
	return ip.To16(), windows.AF_INET6, nil
}

func epSockaddr(ip net.IP, family uint16) windows.RawSockaddrInet {
	if family == windows.AF_INET {
		return sockaddrInet4(ip)
	}
	return sockaddrInet6(ip)
}

func sockaddrInet4(ip net.IP) windows.RawSockaddrInet {
	var sa windows.RawSockaddrInet
	v4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(&sa))
	v4.Family = windows.AF_INET
	copy(v4.Addr[:], ip.To4())
	return sa
}

func sockaddrInet6(ip net.IP) windows.RawSockaddrInet {
	var sa windows.RawSockaddrInet
	v6 := (*windows.RawSockaddrInet6)(unsafe.Pointer(&sa))
	v6.Family = windows.AF_INET6
	copy(v6.Addr[:], ip.To16())
	return sa
}

func familyName(family uint16) string {
	if family == windows.AF_INET {
		return "IPv4"
	}
	return "IPv6"
}

func guidString(g windows.GUID) string {
	return fmt.Sprintf("{%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
		g.Data1, g.Data2, g.Data3,
		g.Data4[0], g.Data4[1], g.Data4[2], g.Data4[3],
		g.Data4[4], g.Data4[5], g.Data4[6], g.Data4[7])
}

// ---------------------------------------------------------------------------
// Crash-recovery state file.
//
// Apply writes the pre-change state (LUID/GUID, original metric, original DNS)
// to %LOCALAPPDATA%\AetherGUI\wgtun-state.json BEFORE the first system mutation,
// then appends every added route as it goes. Revert deletes the file only once
// it has fully succeeded. If the process is killed before Revert runs, the next
// start recovers from the file.
// ---------------------------------------------------------------------------

const stateFileVersion = 1

// metricStateJSON / dnsStateJSON / routeRowJSON are value projections used by
// the state file. They exist because neither ifMetricState (unexported fields)
// nor windows.MibIpForwardRow2 (RawSockaddrInet is a union with padding) can be
// json-marshalled directly.
type metricStateJSON struct {
	Have   bool   `json:"have"`
	Metric uint32 `json:"metric"`
	Auto   uint8  `json:"auto"`
}

type dnsStateJSON struct {
	Path    string `json:"path"`
	Old     string `json:"old"`
	HaveOld bool   `json:"have_old"`
}

type routeRowJSON struct {
	InterfaceLuid uint64 `json:"luid"`
	DestFamily    uint16 `json:"dest_family"`
	DestAddr      []byte `json:"dest_addr"`
	DestPrefixLen uint8  `json:"dest_prefix_len"`
	NextHopFamily uint16 `json:"nexthop_family"`
	NextHopAddr   []byte `json:"nexthop_addr"`
}

// wgtunState is the on-disk recovery state. It holds only the fields needed to
// undo a half-applied takeover — never the private key or WARP identity.
type wgtunState struct {
	Version int                `json:"version"`
	LUID    uint64             `json:"luid"`
	GUID    string             `json:"guid"`
	Metric  [2]metricStateJSON `json:"metric"`
	DNS     dnsStateJSON       `json:"dns"`
	Routes  []routeRowJSON     `json:"routes"`

	// Stacked marks a warp-in-warp (double tunnel) take-over. When set, recovery
	// deletes the inner endpoint's /32 host route (recorded in InnerEp) before
	// the normal route/metric/DNS restore, so the inner layer is torn down first.
	// TEMP-VERIFY: only the inner endpoint route is tracked here; the inner
	// adapter's own metric/DNS are NOT persisted (see StackedTunnel notes).
	Stacked bool         `json:"stacked,omitempty"`
	InnerEp innerEpState `json:"inner_ep,omitempty"`
}

// innerEpState records the inner endpoint's /32 host route pinned onto the
// OUTER wintun adapter — the single route that makes the inner WireGuard UDP
// flow travel inside the outer tunnel (system-route approach, route B).
type innerEpState struct {
	Dst     string `json:"dst"`     // inner endpoint IP (no port)
	Gateway string `json:"gateway"` // next hop = outer wintun address (NOT on-link zero)
	LUID    uint64 `json:"luid"`    // outer wintun adapter LUID
	IfIndex uint32 `json:"ifindex"` // outer wintun adapter ifIndex (diagnostic)
	Family  uint16 `json:"family"`  // windows.AF_INET / AF_INET6
}

// stateDir is where the state file lives; it is a variable so tests can point
// it at a temporary directory instead of %LOCALAPPDATA%\AetherGUI.
var stateDir = config.Dir()

// stateFilePath returns the crash-recovery state file location.
func stateFilePath() string {
	return filepath.Join(stateDir, "wgtun-state.json")
}

// writeStateFile serialises st and fsyncs it to disk (write + Sync + Close).
func writeStateFile(st wgtunState) error {
	raw, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	f, err := os.OpenFile(stateFilePath(), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(raw); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		return err
	}
	return f.Close()
}

// readStateFile loads the state file. os.ErrNotExist is returned unchanged so
// callers can treat "no state" as a normal condition.
func readStateFile() (wgtunState, error) {
	raw, err := os.ReadFile(stateFilePath())
	if err != nil {
		return wgtunState{}, err
	}
	var st wgtunState
	if err := json.Unmarshal(raw, &st); err != nil {
		return wgtunState{}, err
	}
	return st, nil
}

// clearState removes the state file. Idempotent: a missing file is success.
func clearState() error {
	err := os.Remove(stateFilePath())
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

// writeState snapshots the pre-change state (original metric + original DNS +
// LUID/GUID) and fsyncs it. It is called before the first system mutation, so
// it must read the original values itself rather than rely on the stashes that
// setInterfaceMetric / applyDNS fill in later. Routes start empty and are added
// by recordRoute.
func (m *routeManager) writeState() error {
	st := wgtunState{Version: stateFileVersion, LUID: m.luid}
	if guid, err := convertInterfaceLuidToGuid(m.luid); err == nil {
		st.GUID = guidString(guid)
	}

	// Original per-family metric.
	for i, family := range []uint16{windows.AF_INET, windows.AF_INET6} {
		var cur windows.MibIpInterfaceRow
		initializeIpInterfaceEntry(&cur)
		cur.Family = family
		cur.InterfaceLuid = m.luid
		if err := getIpInterfaceEntry(&cur); err == nil {
			st.Metric[i] = metricStateJSON{Have: true, Metric: cur.Metric, Auto: cur.UseAutomaticMetric}
		}
	}

	// Original DNS (NameServer value; the key may not exist yet on a fresh
	// adapter, which is fine — HaveOld stays false).
	if st.GUID != "" {
		path := `SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces\` + st.GUID
		st.DNS.Path = path
		if k, err := registry.OpenKey(registry.LOCAL_MACHINE, path, registry.QUERY_VALUE); err == nil {
			if old, _, err := k.GetStringValue("NameServer"); err == nil {
				st.DNS.Old = old
				st.DNS.HaveOld = true
			}
			_ = k.Close()
		}
	}

	return writeStateFile(st)
}

// recordRoute appends one just-added route to the state file (fsync), so a
// crash mid-Apply still knows exactly which routes to delete on recovery.
func (m *routeManager) recordRoute(r windows.MibIpForwardRow2) error {
	st, err := readStateFile()
	if err != nil {
		return err
	}
	st.Routes = append(st.Routes, routeRowJSON{
		InterfaceLuid: r.InterfaceLuid,
		DestFamily:    r.DestinationPrefix.Prefix.Family,
		DestAddr:      sockaddrAddr(r.DestinationPrefix.Prefix),
		DestPrefixLen: r.DestinationPrefix.PrefixLength,
		NextHopFamily: r.NextHop.Family,
		NextHopAddr:   sockaddrAddr(r.NextHop),
	})
	return writeStateFile(st)
}

// isNotFound reports whether err means "the thing we tried to touch no longer
// exists". For cleanup that is the goal state already reached, so it is treated
// as idempotent success rather than a failure. Only real errors (permission,
// device busy, …) should propagate.
func isNotFound(err error) bool {
	return errors.Is(err, windows.ERROR_NOT_FOUND) ||
		errors.Is(err, windows.ERROR_FILE_NOT_FOUND) ||
		errors.Is(err, registry.ErrNotExist)
}

// isAlreadyExists reports whether err means "the thing we tried to create is
// already there with the parameters we wanted". A crashed prior run can leave
// an identical host route behind (its recovery may not have run); re-adding it
// then fails with ERROR_OBJECT_ALREADY_EXISTS. Treat that as success: the goal
// state is reached, and the record bookkeeping below still tracks it.
func isAlreadyExists(err error) bool {
	return errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) ||
		errors.Is(err, windows.ERROR_ALREADY_EXISTS)
}

// deleteInnerEpRoute rebuilds and deletes the inner endpoint's /32 (or /128)
// on-link host route from the persisted innerEpState. It is the single route
// that pinned the inner endpoint onto the OUTER adapter.
func deleteInnerEpRoute(ep innerEpState) error {
	ip := net.ParseIP(ep.Dst)
	if ip == nil {
		return fmt.Errorf("bad inner endpoint IP %q", ep.Dst)
	}
	family := uint16(windows.AF_INET6)
	prefixLen := uint8(128)
	if v4 := ip.To4(); v4 != nil {
		family = windows.AF_INET
		prefixLen = 32
	}
	gw := net.ParseIP(ep.Gateway)
	var nextHop windows.RawSockaddrInet
	if family == windows.AF_INET {
		if gw != nil && gw.To4() != nil {
			nextHop = sockaddrInet4(gw.To4())
		} else {
			nextHop = sockaddrInet4(net.IPv4zero)
		}
	} else {
		if gw != nil && gw.To16() != nil {
			nextHop = sockaddrInet6(gw.To16())
		} else {
			nextHop = sockaddrInet6(net.IPv6zero)
		}
	}
	row := makeRoute(epSockaddr(ip, family), prefixLen, nextHop, ep.LUID, 0)
	return revertDeleteRoute(&row)
}

// recoverFromState restores metric/DNS/routes left behind by an unclean exit.
// It deletes the state file only if every step succeeds; on any failure the
// file is kept as evidence and the error is returned so the caller logs
// "[wgtun] RECOVERY FAILED, manual cleanup needed: <path>".
func recoverFromState() error {
	path := stateFilePath()
	st, err := readStateFile()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return nil // no residual state — nothing to do
		}
		// Unparseable file (corrupt JSON): park it and keep going, never wedge
		// the user.
		return parkCorruptState(err)
	}

	// Unrecognised version or missing key fields: same "park and continue".
	if st.Version != stateFileVersion || st.LUID == 0 {
		return parkCorruptState(fmt.Errorf("unrecognized version %d or missing LUID", st.Version))
	}

	var errs []error

	// 0. For a stacked (warp-in-warp) take-over, tear down the inner endpoint's
	// host route FIRST: it pins the inner endpoint onto the OUTER adapter, so it
	// must go before the outer adapter's metric/DNS/routes are restored. If the
	// route is already gone (outer adapter vanished), that is the goal state.
	if st.Stacked && st.InnerEp.Dst != "" {
		if err := deleteInnerEpRoute(st.InnerEp); err != nil && !isNotFound(err) {
			errs = append(errs, fmt.Errorf("delete inner endpoint route: %w", err))
		} else {
			logx.Infof("[wgtun] recover: inner endpoint route cleared")
		}
	}

	// 1. Restore per-family metric.
	for i, family := range []uint16{windows.AF_INET, windows.AF_INET6} {
		ms := st.Metric[i]
		if !ms.Have {
			continue
		}
		var set windows.MibIpInterfaceRow
		initializeIpInterfaceEntry(&set)
		set.Family = family
		set.InterfaceLuid = st.LUID
		set.UseAutomaticMetric = ms.Auto
		set.Metric = ms.Metric
		if err := revertSetMetric(&set); err != nil {
			if isNotFound(err) {
				// The interface (and its metric row) is gone already — nothing
				// to restore, so this is success, not a failure to report.
				logx.Infof("[wgtun] recover: metric family %d already absent", family)
				continue
			}
			errs = append(errs, fmt.Errorf("restore metric family %d: %w", family, err))
		}
	}

	// 2. Restore (or remove) DNS.
	if st.DNS.Path != "" {
		if k, err := registry.OpenKey(registry.LOCAL_MACHINE, st.DNS.Path, registry.SET_VALUE); err == nil {
			if st.DNS.HaveOld {
				if err := k.SetStringValue("NameServer", st.DNS.Old); err != nil {
					errs = append(errs, fmt.Errorf("restore DNS: %w", err))
				}
			} else if err := k.DeleteValue("NameServer"); err != nil && !errors.Is(err, registry.ErrNotExist) {
				errs = append(errs, fmt.Errorf("delete DNS: %w", err))
			}
			_ = k.Close()
		} else if isNotFound(err) {
			// The interface's DNS registry key is gone already — nothing to
			// restore.
			logx.Infof("[wgtun] recover: DNS key already absent")
		} else {
			errs = append(errs, fmt.Errorf("open DNS key: %w", err))
		}
	}

	// 3. Delete the recorded routes. NOT_FOUND means the goal is already met.
	for _, rr := range st.Routes {
		row := routeRowToForwardRow(rr)
		if err := revertDeleteRoute(&row); err != nil {
			if isNotFound(err) {
				continue
			}
			errs = append(errs, fmt.Errorf("delete route: %w", err))
		}
	}

	if len(errs) > 0 {
		joined := errors.Join(errs...)
		logx.Errorf("[wgtun] RECOVERY FAILED, manual cleanup needed: %s: %v", path, joined)
		return joined
	}

	if err := clearState(); err != nil {
		return err
	}
	logx.Infof("[wgtun] recovered from previous unclean exit; state file cleared")
	return nil
}

// RecoverState is the start-up entry point: it checks for and cleans up residue
// left by a previous unclean exit. It returns an error only when recovery was
// actually attempted and failed (so the caller can decide whether to block a
// connect); a corrupt/unrecognisable state file is parked and yields nil.
func RecoverState() error {
	return recoverFromState()
}

// ResiduePresent reports (read-only) whether a crash-recovery state file
// currently exists — i.e. there is uncleaned residue from a previous unclean
// exit. It does NOT attempt recovery; that is RecoverState's job. The app layer
// uses this to decide whether to show the residue warning, so the warning
// always reflects the disk's real state (a successful recovery deletes the file
// and the warning clears on the next read without any manual field sync).
func ResiduePresent() bool {
	_, err := os.Stat(stateFilePath())
	return err == nil
}

// parkCorruptState renames a corrupt/unrecognisable state file to *.corrupt so
// the residue is preserved for manual inspection but no longer blocks start-up.
// It never returns an error — a corrupt file must not wedge the user.
func parkCorruptState(reason error) error {
	path := stateFilePath()
	corrupt := path + ".corrupt"
	if err := os.Rename(path, corrupt); err != nil {
		logx.Warnf("[wgtun] state file corrupt (%v); rename to .corrupt failed: %v", reason, err)
	} else {
		logx.Warnf("[wgtun] state file corrupt (%v); parked as %s", reason, corrupt)
	}
	return nil
}

// sockaddrAddr extracts the address bytes from a RawSockaddrInet union by
// interpreting it according to its family. Never memcpy the union whole: it
// contains padding.
func sockaddrAddr(sa windows.RawSockaddrInet) []byte {
	switch sa.Family {
	case windows.AF_INET:
		v4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(&sa))
		return append([]byte(nil), v4.Addr[:]...)
	case windows.AF_INET6:
		v6 := (*windows.RawSockaddrInet6)(unsafe.Pointer(&sa))
		return append([]byte(nil), v6.Addr[:]...)
	}
	return nil
}

// bytesToSockaddr rebuilds a RawSockaddrInet from a family + address bytes.
func bytesToSockaddr(family uint16, addr []byte) windows.RawSockaddrInet {
	var sa windows.RawSockaddrInet
	switch family {
	case windows.AF_INET:
		v4 := (*windows.RawSockaddrInet4)(unsafe.Pointer(&sa))
		v4.Family = windows.AF_INET
		copy(v4.Addr[:], addr)
	case windows.AF_INET6:
		v6 := (*windows.RawSockaddrInet6)(unsafe.Pointer(&sa))
		v6.Family = windows.AF_INET6
		copy(v6.Addr[:], addr)
	}
	return sa
}

// routeRowToForwardRow reconstructs a MibIpForwardRow2 carrying just the fields
// DeleteIpForwardEntry2 needs to identify a route.
func routeRowToForwardRow(rr routeRowJSON) windows.MibIpForwardRow2 {
	return windows.MibIpForwardRow2{
		InterfaceLuid: rr.InterfaceLuid,
		DestinationPrefix: windows.IpAddressPrefix{
			Prefix:       bytesToSockaddr(rr.DestFamily, rr.DestAddr),
			PrefixLength: rr.DestPrefixLen,
		},
		NextHop: bytesToSockaddr(rr.NextHopFamily, rr.NextHopAddr),
	}
}
