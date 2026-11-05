package awg

import (
	"encoding/json"
	"strings"
	"testing"
)

const validProfile = `[Interface]
Address = 10.66.66.2/32
PrivateKey = AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=
DNS = 1.1.1.1
Jc = 4
Jmin = 40
Jmax = 70
S1 = 12
S2 = 13
S3 = 14
S4 = 15
H1 = 1-2
H2 = 2
H3 = 3
H4 = 4
HeaderProtectionKey = AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=
RandomTrailers = on
DisableCookies = off

[Peer]
PublicKey = AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=
Endpoint = awg.example.net:51820
AllowedIPs = 0.0.0.0/0
PersistentKeepalive = 25
`

// TestParseReturnsCanonicalMetadata validates accepted profile metadata and canonical output.
func TestParseReturnsCanonicalMetadata(t *testing.T) {
	profile, err := Parse([]byte(validProfile))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	if profile.Endpoint != "awg.example.net" || profile.EndpointPort != 51820 || len(profile.Address) != 1 || len(profile.AllowedIPs) != 1 || len(profile.DNS) != 1 {
		t.Fatalf("unexpected parsed metadata: %#v", profile)
	}
	if !strings.Contains(string(profile.SecretConfig), "HeaderProtectionKey =") {
		t.Fatal("normalized private config is missing protocol key")
	}
}

// TestParseRejectsUnsafeOrAmbiguousSettings verifies strict rejection without echoing profile data.
func TestParseRejectsUnsafeOrAmbiguousSettings(t *testing.T) {
	cases := map[string]string{
		"hook":            strings.Replace(validProfile, "DNS = 1.1.1.1", "PostUp = touch /tmp/pwned", 1),
		"duplicate":       strings.Replace(validProfile, "DNS = 1.1.1.1", "DNS = 1.1.1.1\nDNS = 9.9.9.9", 1),
		"unknown":         strings.Replace(validProfile, "DNS = 1.1.1.1", "UnknownOption = secret-marker", 1),
		"bad-endpoint":    strings.Replace(validProfile, "awg.example.net:51820", "[fe80::1%eth0]:51820", 1),
		"bad-header-size": strings.Replace(validProfile, "S1 = 12", "S1 = 11", 1),
		"bad-address":     strings.Replace(validProfile, "10.66.66.2/32", "10.66.66.2/99", 1),
		"nonzero-fwmark":  strings.Replace(validProfile, "DNS = 1.1.1.1", "FwMark = 514", 1),
		"bad-range":       strings.Replace(validProfile, "H1 = 1-2", "H1 = 2-1", 1),
		"bad-signature":   strings.Replace(validProfile, "Jc = 4", "I1 = $(touch /tmp/pwned)", 1),
	}
	for name, profile := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := Parse([]byte(profile))
			if err == nil {
				t.Fatal("Parse accepted an unsafe or invalid profile")
			}
			if strings.Contains(err.Error(), "secret-marker") || strings.Contains(err.Error(), "pwned") {
				t.Fatalf("error echoed profile content: %v", err)
			}
		})
	}
}

// TestParseMarksIPv6ProfilesBlocked verifies IPv6 profile fields parse but are explicitly marked for fail-closed routing.
func TestParseMarksIPv6ProfilesBlocked(t *testing.T) {
	for _, profileText := range []string{
		strings.Replace(validProfile, "10.66.66.2/32", "10.66.66.2/32, fd00::2/128", 1),
		strings.Replace(validProfile, "0.0.0.0/0", "0.0.0.0/0, ::/0", 1),
		strings.Replace(validProfile, "DNS = 1.1.1.1", "DNS = 1.1.1.1, 2001:db8::1", 1),
	} {
		profile, err := Parse([]byte(profileText))
		if err != nil {
			t.Fatalf("Parse rejected an IPv6 profile that should be fail-closed: %v", err)
		}
		if !profile.IPv6Blocked {
			t.Fatal("IPv6 profile was not marked for fail-closed routing")
		}
	}
}

// TestParseDoesNotSerializeSecretMaterial ensures the parsed model cannot expose key bytes through JSON.
func TestParseDoesNotSerializeSecretMaterial(t *testing.T) {
	profile, err := Parse([]byte(validProfile))
	if err != nil {
		t.Fatalf("Parse returned error: %v", err)
	}
	encoded, err := json.Marshal(profile)
	if err != nil {
		t.Fatalf("json.Marshal returned error: %v", err)
	}
	if strings.Contains(string(encoded), "AAAAAAAA") || strings.Contains(string(encoded), "HeaderProtectionKey") {
		t.Fatalf("secret material escaped through JSON: %s", encoded)
	}
}
