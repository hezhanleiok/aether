//go:build wgtun

package wgtun

import (
	"syscall"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The IP Helper entry points below are not wrapped by golang.org/x/sys/windows
// (it only exposes GetIpForwardTable2 / GetAdaptersAddresses /
// GetBestInterfaceEx), so they are bound here by hand. All of them live in
// iphlpapi.dll.

var (
	modIPHlpAPI = windows.NewLazySystemDLL("iphlpapi.dll")
	modDNSAPI   = windows.NewLazySystemDLL("dnsapi.dll")

	procConvertInterfaceLuidToIndex = modIPHlpAPI.NewProc("ConvertInterfaceLuidToIndex")
	procConvertInterfaceLuidToGuid  = modIPHlpAPI.NewProc("ConvertInterfaceLuidToGuid")
	procCreateIpForwardEntry2       = modIPHlpAPI.NewProc("CreateIpForwardEntry2")
	procDeleteIpForwardEntry2       = modIPHlpAPI.NewProc("DeleteIpForwardEntry2")
	procGetIpInterfaceEntry         = modIPHlpAPI.NewProc("GetIpInterfaceEntry")
	procSetIpInterfaceEntry         = modIPHlpAPI.NewProc("SetIpInterfaceEntry")
	procInitializeIpInterfaceEntry  = modIPHlpAPI.NewProc("InitializeIpInterfaceEntry")
	procFreeMibTable                = modIPHlpAPI.NewProc("FreeMibTable")
	procDnsFlushResolverCache       = modDNSAPI.NewProc("DnsFlushResolverCache")

	procInitializeUnicastIpAddressEntry = modIPHlpAPI.NewProc("InitializeUnicastIpAddressEntry")
	procCreateUnicastIpAddressEntry     = modIPHlpAPI.NewProc("CreateUnicastIpAddressEntry")
	procDeleteUnicastIpAddressEntry     = modIPHlpAPI.NewProc("DeleteUnicastIpAddressEntry")
)

// convertInterfaceLuidToIndex maps a NET_LUID to its interface index.
func convertInterfaceLuidToIndex(luid uint64) (uint32, error) {
	var idx uint32
	r1, _, _ := procConvertInterfaceLuidToIndex.Call(
		uintptr(unsafe.Pointer(&luid)),
		uintptr(unsafe.Pointer(&idx)),
	)
	if r1 != 0 {
		return 0, syscall.Errno(r1)
	}
	return idx, nil
}

// convertInterfaceLuidToGuid maps a NET_LUID to the adapter GUID used as the
// registry key for per-interface DNS.
func convertInterfaceLuidToGuid(luid uint64) (windows.GUID, error) {
	var guid windows.GUID
	r1, _, _ := procConvertInterfaceLuidToGuid.Call(
		uintptr(unsafe.Pointer(&luid)),
		uintptr(unsafe.Pointer(&guid)),
	)
	if r1 != 0 {
		return windows.GUID{}, syscall.Errno(r1)
	}
	return guid, nil
}

func createIpForwardEntry2(row *windows.MibIpForwardRow2) error {
	r1, _, _ := procCreateIpForwardEntry2.Call(uintptr(unsafe.Pointer(row)))
	if r1 != 0 {
		return syscall.Errno(r1)
	}
	return nil
}

func deleteIpForwardEntry2(row *windows.MibIpForwardRow2) error {
	r1, _, _ := procDeleteIpForwardEntry2.Call(uintptr(unsafe.Pointer(row)))
	if r1 != 0 {
		return syscall.Errno(r1)
	}
	return nil
}

// initializeIpInterfaceEntry zeroes the row and must be called before
// getIpInterfaceEntry / setIpInterfaceEntry so unrelated fields are clean.
func initializeIpInterfaceEntry(row *windows.MibIpInterfaceRow) {
	procInitializeIpInterfaceEntry.Call(uintptr(unsafe.Pointer(row)))
}

func getIpInterfaceEntry(row *windows.MibIpInterfaceRow) error {
	r1, _, _ := procGetIpInterfaceEntry.Call(uintptr(unsafe.Pointer(row)))
	if r1 != 0 {
		return syscall.Errno(r1)
	}
	return nil
}

func setIpInterfaceEntry(row *windows.MibIpInterfaceRow) error {
	r1, _, _ := procSetIpInterfaceEntry.Call(uintptr(unsafe.Pointer(row)))
	if r1 != 0 {
		return syscall.Errno(r1)
	}
	return nil
}

// freeMibTable releases a table returned by GetIpForwardTable2.
func freeMibTable(ptr unsafe.Pointer) {
	procFreeMibTable.Call(uintptr(ptr))
}

// flushResolverCache clears the DNS resolver cache so a just-written per-interface
// DNS takes effect immediately. Returns false when the call failed.
func flushResolverCache() bool {
	r1, _, _ := procDnsFlushResolverCache.Call()
	return r1 != 0
}

// initializeUnicastIpAddressEntry zeroes the row and sets defaults; it must be
// called before filling CreateUnicastIpAddressEntry's row.
func initializeUnicastIpAddressEntry(row *windows.MibUnicastIpAddressRow) {
	procInitializeUnicastIpAddressEntry.Call(uintptr(unsafe.Pointer(row)))
}

// createUnicastIpAddressEntry assigns one unicast address to an interface.
// This is how the wintun adapter gets its tunnel address: without it the
// adapter has no source address, packets leave with a wrong source and
// Cloudflare WARP drops them — the handshake still succeeds (control plane
// never sees the inner source IP) but the data plane is dead, which is exactly
// the "connected, then the whole link black-holed" signature.
func createUnicastIpAddressEntry(row *windows.MibUnicastIpAddressRow) error {
	r1, _, _ := procCreateUnicastIpAddressEntry.Call(uintptr(unsafe.Pointer(row)))
	if r1 != 0 {
		return syscall.Errno(r1)
	}
	return nil
}

// deleteUnicastIpAddressEntry removes one unicast address assignment.
func deleteUnicastIpAddressEntry(row *windows.MibUnicastIpAddressRow) error {
	r1, _, _ := procDeleteUnicastIpAddressEntry.Call(uintptr(unsafe.Pointer(row)))
	if r1 != 0 {
		return syscall.Errno(r1)
	}
	return nil
}
