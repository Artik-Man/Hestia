package panelmodel

// PhysicalInventory describes observed hardware and Hestia-owned client profiles without credentials.
type PhysicalInventory struct {
	Interfaces    []PhysicalInterface `json:"interfaces" nullable:"false"`
	WifiProfiles  []WifiConnection    `json:"wifiProfiles" nullable:"false"`
	WifiAvailable bool                `json:"wifiAvailable"`
}

// PhysicalInterface identifies a device, its carrier and any configured direct exits bound to it.
type PhysicalInterface struct {
	InterfaceName string   `json:"interfaceName" minLength:"1" maxLength:"15"`
	Kind          string   `json:"kind" enum:"ethernet,wifi"`
	Present       bool     `json:"present"`
	Online        bool     `json:"online"`
	ExitIDs       []string `json:"exitIds" nullable:"false"`
}

// WifiConnection reports stored public settings and whether this profile currently owns an active connection.
type WifiConnection struct {
	ID            string `json:"id"`
	InterfaceName string `json:"interfaceName"`
	SSID          string `json:"ssid"`
	Security      string `json:"security" enum:"open,wpa-psk"`
	Band          string `json:"band" enum:"2.4,5"`
	Active        bool   `json:"active"`
}

// WifiConnectionSettings carries write-only credentials. Omission on a WPA profile edit retains the current key.
type WifiConnectionSettings struct {
	InterfaceName string `json:"interfaceName" minLength:"1" maxLength:"15"`
	SSID          string `json:"ssid" minLength:"1" maxLength:"32"`
	Security      string `json:"security" enum:"open,wpa-psk"`
	Band          string `json:"band" enum:"2.4,5"`
	Password      string `json:"password,omitempty" maxLength:"64" writeOnly:"true"`
}

// WifiSaveCommand forwards a path-validated profile ID with settings to the gateway helper.
type WifiSaveCommand struct {
	ID string `json:"id"`
	WifiConnectionSettings
}
