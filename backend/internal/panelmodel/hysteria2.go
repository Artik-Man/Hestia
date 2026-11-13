package panelmodel

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net/netip"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Hysteria2Settings holds editable public settings for one single-port TLS connection.
type Hysteria2Settings struct {
	Name           string      `json:"name" minLength:"1" maxLength:"80"`
	Underlays      UnderlayIDs `json:"underlays,omitzero" maxItems:"64" nullable:"false"`
	Underlay       string      `json:"underlay,omitempty" minLength:"1" maxLength:"63"`
	Server         string      `json:"server" minLength:"1" maxLength:"253"`
	Port           int         `json:"port" minimum:"1" maximum:"65535"`
	ServerName     string      `json:"serverName,omitempty" maxLength:"253"`
	CertificatePEM string      `json:"certificatePEM,omitempty" maxLength:"24576"`
}

// Hysteria2WriteRequest carries group placement on creation and an optional replacement password on edit.
type Hysteria2WriteRequest struct {
	Hysteria2Settings
	Group    string `json:"group,omitempty" maxLength:"63"`
	Password string `json:"password,omitempty" maxLength:"2048" writeOnly:"true"`
}

// Hysteria2Connection returns public settings and committed placement without credential fields.
type Hysteria2Connection struct {
	Enabled bool `json:"enabled"`
	Hysteria2Settings
	ID             string `json:"id" format:"uuid"`
	Group          string `json:"group" minLength:"1"`
	Priority       int    `json:"priority" minimum:"1"`
	ActiveUnderlay string `json:"activeUnderlay,omitempty"`
}

// Hysteria2ConnectionProfile contains credentials only for an explicitly requested individual edit.
type Hysteria2ConnectionProfile struct {
	Hysteria2Connection
	Password string `json:"password" minLength:"1"`
}

// EffectiveUnderlays returns the ordered preference, upgrading an earlier physical binding in memory.
func (s Hysteria2Settings) EffectiveUnderlays() UnderlayIDs {
	if s.Underlays != nil {
		return s.Underlays
	}
	if s.Underlay != "" {
		return UnderlayIDs{s.Underlay}
	}
	return UnderlayIDs{}
}

// Hysteria2Command associates a validated ID with settings on the restricted helper pipe.
type Hysteria2Command struct {
	ID string `json:"id"`
	Hysteria2WriteRequest
}

var hysteriaLabel = regexp.MustCompile("^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
var hysteriaExitID = regexp.MustCompile("^[a-z0-9][a-z0-9-]{0,62}$")

// validHysteriaHost accepts an unbracketed IP address or an ASCII DNS hostname for dialing and TLS.
func validHysteriaHost(host string) bool {
	if ip, err := netip.ParseAddr(host); err == nil {
		return ip.Zone() == ""
	}
	if len(host) > 253 || strings.Trim(host, "0123456789.") == "" {
		return false
	}
	for _, label := range strings.Split(strings.TrimSuffix(host, "."), ".") {
		if !hysteriaLabel.MatchString(label) {
			return false
		}
	}
	return true
}

// validHysteriaCertificates accepts an empty system trust override or a complete PEM bundle of public X.509 certificates.
func validHysteriaCertificates(bundle string) bool {
	if bundle == "" {
		return true
	}
	if len(bundle) > 24576 {
		return false
	}
	const begin, end = "-----BEGIN CERTIFICATE-----", "-----END CERTIFICATE-----"
	data := bytes.TrimSpace([]byte(bundle))
	if len(data) == 0 {
		return false
	}
	for len(data) > 0 {
		if !bytes.HasPrefix(data, []byte(begin)) {
			return false
		}
		body, tail, ok := bytes.Cut(data[len(begin):], []byte(end))
		if !ok || bytes.Contains(body, []byte("-----BEGIN")) {
			return false
		}
		block, rest := pem.Decode(data[:len(data)-len(tail)])
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(rest) != 0 {
			return false
		}
		if _, err := x509.ParseCertificate(block.Bytes); err != nil {
			return false
		}
		data = bytes.TrimSpace(tail)
	}
	return true
}

// ValidateHysteria2 checks endpoint, credentials, certificates and placement without returning input values.
func ValidateHysteria2(req Hysteria2WriteRequest, update bool) error {
	switch {
	case !utf8.ValidString(req.Name) || req.Name == "" || req.Name != strings.TrimSpace(req.Name) || utf8.RuneCountInString(req.Name) > 80 || strings.IndexFunc(req.Name, unicode.IsControl) >= 0:
		return errors.New("Недопустимое название подключения")
	case (req.Underlay != "" && (!hysteriaExitID.MatchString(req.Underlay) || req.Underlays != nil)) || len(req.Underlays) > 64:
		return errors.New("Выберите физическое подключение")
	case (!update && !hysteriaExitID.MatchString(req.Group)) || (update && req.Group != ""):
		return errors.New("Недопустимое назначение группы")
	case !validHysteriaHost(req.Server) || req.Port < 1 || req.Port > 65535:
		return errors.New("Недопустимый адрес или UDP-порт сервера")
	case req.ServerName != "" && !validHysteriaHost(req.ServerName):
		return errors.New("Недопустимое имя сервера TLS")
	case !validHysteriaCertificates(req.CertificatePEM):
		return errors.New("Ожидается публичный сертификат X.509 в формате PEM")
	case !update && req.Password == "" || len(req.Password) > 2048 || strings.IndexFunc(req.Password, unicode.IsControl) >= 0:
		return errors.New("Недопустимый пароль подключения")
	default:
		return nil
	}
}
