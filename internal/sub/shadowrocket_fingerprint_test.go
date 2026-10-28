package sub

import (
	"strings"
	"testing"
)

// Shadowrocket re-applies a subscription node's link parameters over a manual
// fingerprint edit, so the raw vless:// link must carry a profile that sends
// X25519MLKEM768. The Shadowrocket-only field overrides fp in share links.
func TestApplyShareRealityParams_ShadowrocketFingerprintOverridesFP(t *testing.T) {
	stream := map[string]any{
		"realitySettings": map[string]any{
			"serverNames": []any{"reality.example.com"},
			"shortIds":    []any{"ab12cd"},
			"settings": map[string]any{
				"publicKey":               "PBKvalue",
				"fingerprint":             "chrome",
				"shadowrocketFingerprint": "Chrome140",
				"spiderX":                 "/mypath",
			},
		},
	}
	params := map[string]string{}
	applyShareRealityParams(stream, params, "user")

	if got := params["fp"]; got != "Chrome140" {
		t.Fatalf("fp = %q, want Chrome140", got)
	}
	if got := params["pbk"]; got != "PBKvalue" {
		t.Fatalf("pbk = %q, want PBKvalue", got)
	}
}

func TestApplyShareRealityParams_NoShadowrocketFingerprintKeepsFP(t *testing.T) {
	stream := map[string]any{
		"realitySettings": map[string]any{
			"serverNames": []any{"reality.example.com"},
			"shortIds":    []any{"ab12cd"},
			"settings": map[string]any{
				"publicKey":   "PBKvalue",
				"fingerprint": "firefox",
				"spiderX":     "/mypath",
			},
		},
	}
	params := map[string]string{}
	applyShareRealityParams(stream, params, "user")

	if got := params["fp"]; got != "firefox" {
		t.Fatalf("fp = %q, want firefox", got)
	}
}

// The same override must reach the VLESS share link built by genVlessLink.
func TestGenVlessLink_ShadowrocketFingerprint(t *testing.T) {
	stream := `{
		"network":"tcp","security":"reality",
		"tcpSettings":{"header":{"type":"none"}},
		"realitySettings":{
			"serverNames":["reality.example.com"],
			"shortIds":["ab12cd"],
			"settings":{
				"publicKey":"PBKvalue",
				"fingerprint":"chrome",
				"shadowrocketFingerprint":"Chrome140",
				"spiderX":"/mypath"
			}
		}
	}`
	s := &SubService{}
	link := s.genVlessLink(shareLinkInbound(stream), "user")

	if !strings.Contains(link, "fp=Chrome140") {
		t.Fatalf("reality link does not carry the Shadowrocket fingerprint: %s", link)
	}
	if strings.Contains(link, "fp=chrome") {
		t.Fatalf("reality link still carries the generic chrome fingerprint: %s", link)
	}
}
