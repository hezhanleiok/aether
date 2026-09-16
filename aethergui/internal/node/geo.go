package node

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// GeoInfo is what a geolocation API tells us about an exit IP.
type GeoInfo struct {
	IP       string  `json:"ip"`
	Country  string  `json:"country"`
	CountryCode string `json:"country_code"`
	City     string  `json:"city"`
	ASN      string  `json:"asn"`
	ISP      string  `json:"isp"`
	Lat      float64 `json:"lat"`
	Lon      float64 `json:"lon"`
	Flag     string  `json:"flag"`
}

// FlagFromCode returns the emoji flag for an ISO country code ("jp" → 🇯🇵).
func FlagFromCode(code string) string {
	code = strings.ToLower(strings.TrimSpace(code))
	if len(code) != 2 {
		return "🌐"
	}
	const base = 0x1F1E6
	r := []rune{
		rune(base + int(code[0]) - 'a'),
		rune(base + int(code[1]) - 'a'),
	}
	return string(r)
}

// GeoLookup queries ip-api.com through the given http client (the tunnel's).
// Failure here never blocks a VPN connection: callers treat errors as soft.
func GeoLookup(ctx context.Context, client *http.Client, ip string) (GeoInfo, error) {
	info := GeoInfo{IP: ip}
	if client == nil {
		client = &http.Client{Timeout: 6 * time.Second}
	}
	url := "http://ip-api.com/json/" + ip + "?fields=status,message,country,countryCode,city,asn,isp,lat,lon,query"
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return info, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return info, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return info, err
	}
	var raw struct {
		Status      string  `json:"status"`
		Message     string  `json:"message"`
		Country     string  `json:"country"`
		CountryCode string  `json:"countryCode"`
		City        string  `json:"city"`
		Asn         int     `json:"as"`
		Org         string  `json:"org"`
		Isp         string  `json:"isp"`
		Lat         float64 `json:"lat"`
		Lon         float64 `json:"lon"`
		Query       string  `json:"query"`
	}
	if err := json.Unmarshal(body, &raw); err != nil {
		return info, fmt.Errorf("geo json: %w", err)
	}
	if raw.Status == "fail" {
		return info, fmt.Errorf("geo api: %s", raw.Message)
	}
	info.Country = raw.Country
	info.CountryCode = raw.CountryCode
	info.City = raw.City
	info.ASN = fmt.Sprintf("AS%d", raw.Asn)
	info.ISP = firstNonEmpty(raw.Isp, raw.Org)
	info.Lat = raw.Lat
	info.Lon = raw.Lon
	info.Flag = FlagFromCode(raw.CountryCode)
	return info, nil
}

// IPv6Lookup fetches the caller's public IPv6 ("" when absent).
func IPv6Lookup(ctx context.Context, client *http.Client) string {
	if client == nil {
		client = &http.Client{Timeout: 6 * time.Second}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	req, _ := http.NewRequestWithContext(ctx, "GET", "https://api64.ipify.org?format=json", nil)
	resp, err := client.Do(req)
	if err != nil {
		return ""
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	var out struct{ IP string `json:"ip"` }
	if json.Unmarshal(body, &out) == nil && strings.Contains(out.IP, ":") {
		return out.IP
	}
	return ""
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}
