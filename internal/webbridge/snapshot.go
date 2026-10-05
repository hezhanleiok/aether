//go:build windows

package webbridge

import (
	"net"
	"strings"
	"time"

	"github.com/aethergui/aethergui/internal/app"
	"github.com/aethergui/aethergui/internal/config"
	"github.com/aethergui/aethergui/internal/killswitch"
	"github.com/aethergui/aethergui/internal/logx"
	"github.com/aethergui/aethergui/internal/node"
	"github.com/aethergui/aethergui/internal/sysproxy"
	"github.com/aethergui/aethergui/internal/vpn"
)

// Protocol is one transport the user can switch to from the main screen.
type Protocol struct {
	Key   string `json:"key"` // auto | wg | awg | h3 | mim | gool
	Label string `json:"label"`
	Mode  string `json:"mode"`
	Proto string `json:"proto"`
	UseH2 bool   `json:"useH2"`
	// Native forces the native WireGuard backend (wintun + wireguard-go).
	// Only it can send AmneziaWG junk, so AWG implies it.
	Native bool `json:"native"`
	// AWG turns the AmneziaWG junk decoys on (see config.Settings.AWGJunk).
	AWG bool `json:"awg"`
	// Note is an honest caveat shown next to the picker. It is only ever set
	// for transports that were measured failing or that are only partly
	// implemented — never as a guess.
	Note string `json:"note,omitempty"`
}

// Protocols is the switcher model (order matters: the grid renders it as-is).
var Protocols = []Protocol{
	{Key: "wg", Label: "WireGuard", Mode: string(config.ModeWARP), Proto: "wg"},
	// AWG (AmneziaWG): WireGuard with junk decoys in front of every handshake
	// initiation. It replaced MasqueH2 in this slot: MASQUE/H2 was measured
	// failing with core 2.1.0 on this network (the TCP/443 TLS handshake is
	// reset with os error 10054/10060 with fragmentation on and off alike),
	// while the WireGuard-class transports do connect here.
	//
	// Scope note (honest, from the code): only the junk half is implemented —
	// Jc/Jmin/Jmax. AmneziaWG's fake first packet (I1) is NOT, and warpscout
	// reports that I1, not the junk sizes, is what usually gets a connection
	// past a filter. Expect "handshake no longer opens with a bare 148-byte
	// initiation", not "unblockable".
	{Key: "awg", Label: "AWG", Mode: string(config.ModeWireGuard), Proto: "wg", Native: true, AWG: true,
		Note: "AmneziaWG 混淆：仅实现 junk（Jc/Jmin/Jmax），I1 伪装首包未实现；需要 native 后端 + 管理员权限"},
	{Key: "h3", Label: "MasqueH3", Mode: string(config.ModeMasqueH3), Proto: "masque"},
	// MIM's inner hop rides QUIC by default, and that is the first thing DPI
	// breaks: measured on this network, every inner edge closed with QUIC code
	// 0x128 before validation, while the H2 path brought up both hops
	// (outer + inner) reliably. H2 is therefore the default here; --mim --h3
	// stays reachable for networks where QUIC gets through.
	// Both MIM carriers were measured failing under core 2.1.0: HTTP/3 inner
	// hops close with QUIC code 0x128, and the HTTP/2 path dies in the TLS
	// handshake. Kept selectable, and flagged rather than silently failing.
	{Key: "mim", Label: "MASQUE-in-MASQUE", Mode: string(config.ModeMasqueH3), Proto: "mim", UseH2: true,
		Note: "实测（Core 2.1.0）：HTTP/3 内层被掐断、HTTP/2 握手失败，可能无法连接"},
	{Key: "gool", Label: "Gool", Mode: string(config.ModeGool), Proto: "gool"},
	{Key: "auto", Label: "自动最佳", Mode: string(config.ModeAuto), Proto: ""},
}

// protocolList is the switcher model for this build. It is Protocols with the
// AWG entry flagged when the native backend is missing: without it there is
// nothing that can send AmneziaWG junk, so the entry would otherwise look
// selectable and quietly behave like plain WireGuard.
func protocolList() []Protocol {
	if app.NativeAvailable() {
		return Protocols
	}
	out := make([]Protocol, len(Protocols))
	copy(out, Protocols)
	for i := range out {
		if out[i].AWG {
			out[i].Note = "当前构建未编译 native 后端（-tags wgtun）：AWG 不可用"
		}
	}
	return out
}

// ProtocolByKey resolves a switcher entry.
func ProtocolByKey(key string) (Protocol, bool) {
	for _, p := range Protocols {
		if p.Key == key {
			return p, true
		}
	}
	return Protocol{}, false
}

// ProtocolKey maps the persisted settings onto a switcher entry.
func ProtocolKey(s config.Settings) string {
	switch {
	case s.Protocol == "mim":
		return "mim"
	case s.Mode == config.ModeGool || s.Protocol == "gool":
		return "gool"
	case s.Mode == config.ModeWARP || s.Mode == config.ModeWireGuard || s.Protocol == "wg":
		// AWG is WireGuard + obfuscation on the native backend, so it is a
		// property of the WireGuard-class modes rather than a mode of its own.
		// Either half (junk decoys or the fake first packet) makes it AWG.
		if s.AWGJunk || (s.AWGI1 != "" && !strings.EqualFold(s.AWGI1, "none")) {
			return "awg"
		}
		return "wg"
	case s.UseH2 && (s.Mode == config.ModeMasqueH2 || s.Mode == config.ModeMasqueH3 || s.Protocol == "masque"):
		return "h2"
	case s.Mode == config.ModeMasqueH3 || s.Protocol == "masque":
		return "h3"
	default:
		return "auto"
	}
}

// ProtocolLabel is the human name of the active transport.
func ProtocolLabel(s config.Settings) string {
	if p, ok := ProtocolByKey(ProtocolKey(s)); ok {
		return p.Label
	}
	return "自动"
}

// VersionInfo describes the GUI and the managed core.
type VersionInfo struct {
	GUI         string `json:"gui"`
	Core        string `json:"core"`
	CorePath    string `json:"corePath"`
	CoreHealth  string `json:"coreHealth"`
	CoreRunning bool   `json:"coreRunning"`
	Backend     string `json:"backend"`
	DataDir     string `json:"dataDir"`
	LogFile     string `json:"logFile"`
}

// VPNInfo is the connection state shown on the home screen.
type VPNInfo struct {
	Status       string    `json:"status"`
	Mode         string    `json:"mode"`
	ModeLabel    string    `json:"modeLabel"`
	ProtocolKey  string    `json:"protocolKey"`
	ProtocolName string    `json:"protocolName"`
	ExitIP       string    `json:"exitIP"`
	ExitCountry  string    `json:"exitCountry"`
	ExitFlag     string    `json:"exitFlag"`
	LatencyMs    int64     `json:"latencyMs"`
	Gateway      string    `json:"gateway"`
	GatewayName  string    `json:"gatewayName"`
	Error        string    `json:"error"`
	Phase        string    `json:"phase"`
	StartedAt    time.Time `json:"startedAt"`
	DurationSec  int64     `json:"durationSec"`
	LocalIP      string    `json:"localIP"`

	// Chained exit (Aether -> Psiphon).
	Chain       string   `json:"chain"`       // "" | psiphon
	ChainRegion string   `json:"chainRegion"` // country the chain left from
	ExitRegions []string `json:"exitRegions"` // exits Psiphon currently offers
}

// TrafficInfo is the throughput block (live + cumulative).
type TrafficInfo struct {
	DownBps     int64 `json:"downBps"`
	UpBps       int64 `json:"upBps"`
	DownTotal   int64 `json:"downTotal"`
	UpTotal     int64 `json:"upTotal"`
	DurationSec int64 `json:"durationSec"`
	Valid       bool  `json:"valid"`
}

// SystemInfo reports the Windows-side takeovers.
type SystemInfo struct {
	SysProxy   bool `json:"sysProxy"`
	KillSwitch bool `json:"killSwitch"`
	AutoStart  bool `json:"autoStart"`
	// NativeResidue is the residue-left-behind prompt from a previous unclean
	// native-WG exit (empty when clean); the UI shows it and asks for elevation.
	NativeResidue string `json:"nativeResidue"`
}

// Snapshot is the complete UI state, pushed on every meaningful change.
type Snapshot struct {
	Version    VersionInfo     `json:"version"`
	VPN        VPNInfo         `json:"vpn"`
	Traffic    TrafficInfo     `json:"traffic"`
	Settings   config.Settings `json:"settings"`
	Protocols  []Protocol      `json:"protocols"`
	ActiveKey  string          `json:"activeProtocol"`
	Nodes      []node.Node     `json:"nodes"`
	ActiveNode string          `json:"activeNode"`
	Testing    bool            `json:"nodesTesting"`
	Probing    bool            `json:"nodesProbing"`
	System     SystemInfo      `json:"system"`
	Now        int64           `json:"now"`
}

// Snapshot builds the current UI state.
func (b *Bridge) snapshot() Snapshot {
	a := b.app
	st := a.VPN.State()
	s := a.Settings

	active := ProtocolKey(s)
	gwName := ProtocolLabel(s)

	dur := int64(0)
	if !st.StartedAt.IsZero() && (st.Status == vpn.StatusConnected || st.Status == vpn.StatusConnecting ||
		st.Status == vpn.StatusReconnecting || st.Status == vpn.StatusAetherUp ||
		st.Status == vpn.StatusStartingPsiphon || st.Status == vpn.StatusPsiphonConnecting) {
		dur = int64(time.Since(st.StartedAt).Seconds())
	}

	tr := a.Traffic.Current()
	nodes := a.Nodes()
	if nodes == nil {
		nodes = []node.Node{}
	}

	return Snapshot{
		Version: VersionInfo{
			GUI:         b.version,
			Core:        a.Core.Version(),
			CorePath:    a.Core.Path(),
			CoreHealth:  a.Core.Health().String(),
			CoreRunning: a.Core.Running(),
			Backend:     a.Core.Backend().Kind(),
			DataDir:     config.Dir(),
			LogFile:     logx.FilePath(),
		},
		VPN: VPNInfo{
			Status:       string(st.Status),
			Mode:         string(st.Mode),
			ModeLabel:    modeLabel(st.Mode),
			ProtocolKey:  active,
			ProtocolName: gwName,
			ExitIP:       st.ExitIP,
			ExitCountry:  st.ExitCountry,
			ExitFlag:     st.ExitFlag,
			LatencyMs:    st.LatencyMs,
			Gateway:      st.Gateway,
			GatewayName:  gatewayName(a, st.Gateway),
			Error:        st.Error,
			Phase:        st.Phase,
			StartedAt:    st.StartedAt,
			DurationSec:  dur,
			LocalIP:      localIPv4(),
			Chain:        st.Chain,
			ChainRegion:  st.ChainRegion,
			ExitRegions:  st.ExitRegions,
		},
		Traffic: TrafficInfo{
			DownBps:     tr.DownBytesPerSec,
			UpBps:       tr.UpBytesPerSec,
			DownTotal:   tr.DownTotal,
			UpTotal:     tr.UpTotal,
			DurationSec: dur,
			Valid:       tr.Valid,
		},
		Settings:   s,
		Protocols:  protocolList(),
		ActiveKey:  active,
		Nodes:      nodes,
		ActiveNode: a.ActiveNodeID(),
		Testing:    a.NodesTesting(),
		Probing:    a.NodesProbing(),
		System: SystemInfo{
			SysProxy:      sysproxy.Taken(),
			KillSwitch:    killswitch.Enabled(),
			AutoStart:     s.AutoStart,
			NativeResidue: a.NativeResidue(),
		},
		Now: time.Now().UnixMilli(),
	}
}

func modeLabel(m config.Mode) string {
	switch m {
	case config.ModeFullVPN:
		return "全局 VPN"
	case config.ModeProxy:
		return "全局代理"
	case config.ModeSplit:
		return "规则分流"
	case config.ModeDirect:
		return "直连"
	case config.ModeWARP, config.ModeWireGuard:
		return "WARP (WireGuard)"
	case config.ModeGool:
		return "Gool (WARP-in-WARP)"
	case config.ModeMasqueH2:
		return "MASQUE / HTTP2"
	case config.ModeMasqueH3:
		return "MASQUE / HTTP3"
	default:
		return "自动"
	}
}

// gatewayName turns a cached gateway address into the friendly node name.
func gatewayName(a *app.App, gw string) string {
	if gw == "" {
		return ""
	}
	for _, n := range a.Nodes() {
		if n.Addr() == gw && n.Country != "" {
			return n.Flag + " " + n.Country
		}
	}
	return gw
}

// localIPv4 returns the machine's LAN address (empty when offline).
func localIPv4() string {
	addrs, err := net.InterfaceAddrs()
	if err != nil {
		return ""
	}
	fallback := ""
	for _, a := range addrs {
		ipn, ok := a.(*net.IPNet)
		if !ok || ipn.IP.IsLoopback() {
			continue
		}
		v4 := ipn.IP.To4()
		if v4 == nil {
			continue
		}
		if v4[0] == 169 && v4[1] == 254 {
			continue
		}
		if v4.IsPrivate() {
			return v4.String()
		}
		if fallback == "" {
			fallback = v4.String()
		}
	}
	return fallback
}
