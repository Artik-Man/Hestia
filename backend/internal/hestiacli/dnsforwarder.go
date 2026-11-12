package hestiacli

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"regexp"
	"slices"
	"strings"
	"syscall"
	"time"
)

const (
	keeneticNDMCPath        = "/bin/ndmc"
	keeneticDNSConfigPath   = "/opt/etc/hestia/dns.json"
	hestiaDNSProfile        = "HestiaDNS"
	hestiaDNSProfileLabel   = "Hestia managed DNS forwarder"
	hestiaEngineProfileName = "interceptor"
)

var dnsInterfacePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.:/-]{0,63}$`)
var terminalControlPattern = regexp.MustCompile(`\x1b\[[0-?]*[ -/]*[@-~]`)

// dnsForwarderConfig contains only the Hestia listener coordinates needed to create a router profile.
type dnsForwarderConfig struct {
	Listen string            `json:"listen"`
	Router string            `json:"router"`
	Direct map[string]string `json:"directResolvers"`
}

// dnsForwarderProfile describes the narrow subset of Keenetic DNS-proxy settings managed by Hestia.
type dnsForwarderProfile struct {
	Listen             netip.AddrPort
	Interfaces         []string
	ExpectedInterfaces []string
	EngineOwned        bool
	Present            bool
	Exact              bool
}

// interfaceFlags collects repeatable LAN interface arguments for explicit profile assignment.
type interfaceFlags []string

// String returns the comma-separated interface values for flag help and diagnostics.
func (values *interfaceFlags) String() string {
	return strings.Join(*values, ",")
}

// Set appends one validated Keenetic interface name to the selected profile assignment list.
func (values *interfaceFlags) Set(value string) error {
	if !dnsInterfacePattern.MatchString(value) || strings.ContainsAny(value, "\"' `") {
		return errors.New("interface name contains unsupported characters")
	}
	if slices.Contains(*values, value) {
		return errors.New("interface name is repeated")
	}
	*values = append(*values, value)
	return nil
}

// RunDNSForwarder reports, enables, or disables the explicit Hestia DNS profile on Keenetic.
func RunDNSForwarder(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return errors.New("dns-forwarder requires enable, status, or disable")
	}
	switch args[0] {
	case "enable":
		return enableDNSForwarder(ctx, args[1:], stdout, stderr)
	case "status":
		if len(args) != 1 {
			return errors.New("dns-forwarder status accepts no options")
		}
		profile, err := readDNSForwarderProfile(ctx)
		if err != nil {
			return err
		}
		return writeDNSForwarderStatus(stdout, profile)
	case "disable":
		if len(args) != 1 {
			return errors.New("dns-forwarder disable accepts no options")
		}
		return disableDNSForwarder(ctx, stdout)
	default:
		return errors.New("dns-forwarder requires enable, status, or disable")
	}
}

// enableDNSForwarder validates the live listener and existing router configuration before adding an owned profile.
func enableDNSForwarder(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("dns-forwarder enable", flag.ContinueOnError)
	flags.SetOutput(stderr)
	var interfaces interfaceFlags
	flags.Var(&interfaces, "interface", "private client-facing interface (repeat for each LAN segment)")
	configPath := flags.String("config", keeneticDNSConfigPath, "Hestia DNS service configuration")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 || len(interfaces) == 0 {
		return errors.New("enable requires one or more -interface values")
	}
	slices.Sort(interfaces)
	if os.Geteuid() != 0 {
		return errors.New("dns-forwarder enable must run as root on Keenetic")
	}
	config, err := readDNSForwarderConfig(*configPath)
	if err != nil {
		return err
	}
	if err = checkDNSForwarderListener(ctx, config); err != nil {
		return err
	}
	current, err := readDNSForwarderProfile(ctx)
	if err != nil {
		return err
	}
	if current.Present {
		listen, _ := netip.ParseAddrPort(config.Listen)
		if !current.Exact || current.Listen != listen || !slices.Equal(current.Interfaces, interfaces) {
			return errors.New("Hestia DNS profile exists with different settings; refusing to overwrite it")
		}
		return writeDNSForwarderStatus(stdout, current)
	}
	if err = checkInterfaceAssignments(ctx, interfaces); err != nil {
		return err
	}
	if err = ensureInterfacesExist(ctx, interfaces); err != nil {
		return err
	}
	listen, _ := netip.ParseAddrPort(config.Listen)
	engineOwned, err := configureDNSForwarder(ctx, listen, interfaces)
	if err != nil {
		return err
	}
	profile, err := readDNSForwarderProfile(ctx)
	if err != nil || !profile.Exact || profile.Listen != listen || !slices.Equal(profile.Interfaces, interfaces) {
		rollbackErr := rollbackDNSForwarder(ctx, interfaces, true, engineOwned)
		if rollbackErr != nil {
			return errors.New("Keenetic DNS profile verification failed and rollback was incomplete")
		}
		return errors.New("Keenetic DNS profile did not match the requested configuration")
	}
	return writeDNSForwarderStatus(stdout, profile)
}

// disableDNSForwarder removes only a complete profile still matching Hestia's ownership marker and upstream.
func disableDNSForwarder(ctx context.Context, stdout io.Writer) error {
	if os.Geteuid() != 0 {
		return errors.New("dns-forwarder disable must run as root on Keenetic")
	}
	profile, err := readDNSForwarderProfile(ctx)
	if err != nil {
		return err
	}
	if !profile.Present {
		_, err = fmt.Fprintln(stdout, "Hestia DNS profile is not configured")
		return err
	}
	if !profile.Exact {
		return errors.New("Hestia DNS profile changed; refusing to remove router settings")
	}
	var removed []string
	for _, name := range profile.Interfaces {
		if err = runNDMC(ctx, "no dns-proxy filter assign interface profile "+name); err != nil {
			return restoreDNSForwarder(ctx, profile, removed, false, false, "cannot remove Hestia DNS interface assignment")
		}
		removed = append(removed, name)
	}
	if err = runNDMC(ctx, "no dns-proxy filter profile "+hestiaDNSProfile); err != nil {
		return restoreDNSForwarder(ctx, profile, removed, false, false, "cannot remove Hestia DNS profile")
	}
	profileRemoved := true
	engineRemoved := false
	if profile.EngineOwned && !otherDNSFilterSettings(ctx) {
		if err = runNDMC(ctx, "no dns-proxy filter engine"); err != nil {
			return restoreDNSForwarder(ctx, profile, removed, profileRemoved, false, "cannot remove Hestia DNS filter engine")
		}
		engineRemoved = true
	}
	if err = runNDMC(ctx, "system configuration save"); err != nil {
		return restoreDNSForwarder(ctx, profile, removed, profileRemoved, engineRemoved, "Keenetic DNS profile was removed but could not be saved")
	}
	_, err = fmt.Fprintln(stdout, "Hestia DNS profile disabled")
	return err
}

// restoreDNSForwarder reverses a partial disable transaction using the exact profile snapshot read before mutation.
func restoreDNSForwarder(ctx context.Context, profile dnsForwarderProfile, interfaces []string, profileRemoved, engineRemoved bool, cause string) error {
	var failures []error
	if engineRemoved {
		failures = append(failures, runNDMC(ctx, "dns-proxy filter engine "+hestiaEngineProfileName))
	}
	if profileRemoved {
		failures = append(failures, runNDMC(ctx, "dns-proxy filter profile "+hestiaDNSProfile))
		failures = append(failures, runNDMC(ctx, "dns-proxy filter profile "+hestiaDNSProfile+" description \""+engineOwnershipDescription(profile.EngineOwned, profile.ExpectedInterfaces)+"\""))
		failures = append(failures, runNDMC(ctx, "dns-proxy filter profile "+hestiaDNSProfile+" dns53 upstream "+profile.Listen.String()))
	}
	for _, name := range interfaces {
		failures = append(failures, runNDMC(ctx, "dns-proxy filter assign interface profile "+name+" "+hestiaDNSProfile))
	}
	failures = append(failures, runNDMC(ctx, "system configuration save"))
	if rollbackErr := errors.Join(failures...); rollbackErr != nil {
		return errors.New(cause + "; restoring the Hestia DNS profile was incomplete")
	}
	return errors.New(cause)
}

// configureDNSForwarder creates the isolated profile, assigns it to requested segments, and saves one config generation.
func configureDNSForwarder(ctx context.Context, listen netip.AddrPort, interfaces []string) (bool, error) {
	engineOwned := false
	lines, err := readDNSProxyLines(ctx)
	if err != nil {
		return false, err
	}
	if !slices.Contains(lines, "filter engine "+hestiaEngineProfileName) {
		if hasDNSFilterEngine(lines) {
			return false, errors.New("a different Keenetic DNS filter engine is already configured")
		}
		if hasOtherDNSFilterSettings(lines) {
			return false, errors.New("other Keenetic DNS profiles exist; refusing to enable the global filter engine")
		}
		if err = runNDMC(ctx, "dns-proxy filter engine "+hestiaEngineProfileName); err != nil {
			return false, errors.New("cannot enable the Keenetic DNS profile engine")
		}
		engineOwned = true
	}
	if err = runNDMC(ctx, "dns-proxy filter profile "+hestiaDNSProfile); err != nil {
		rollbackErr := rollbackDNSForwarder(ctx, nil, false, engineOwned)
		if rollbackErr != nil {
			return engineOwned, errors.New("Keenetic DNS profile setup failed and rollback was incomplete")
		}
		return engineOwned, errors.New("Keenetic rejected the Hestia DNS profile configuration")
	}
	if err = runNDMC(ctx, "dns-proxy filter profile "+hestiaDNSProfile+" description \""+engineOwnershipDescription(engineOwned, interfaces)+"\""); err != nil {
		rollbackErr := rollbackDNSForwarder(ctx, nil, true, engineOwned)
		if rollbackErr != nil {
			return engineOwned, errors.New("Keenetic DNS profile setup failed and rollback was incomplete")
		}
		return engineOwned, errors.New("Keenetic rejected the Hestia DNS profile configuration")
	}
	if err = runNDMC(ctx, "dns-proxy filter profile "+hestiaDNSProfile+" dns53 upstream "+listen.String()); err != nil {
		rollbackErr := rollbackDNSForwarder(ctx, nil, true, engineOwned)
		if rollbackErr != nil {
			return engineOwned, errors.New("Keenetic DNS profile setup failed and rollback was incomplete")
		}
		return engineOwned, errors.New("Keenetic rejected the Hestia DNS profile configuration")
	}
	var assigned []string
	for _, name := range interfaces {
		if err = runNDMC(ctx, "dns-proxy filter assign interface profile "+name+" "+hestiaDNSProfile); err != nil {
			rollbackErr := rollbackDNSForwarder(ctx, assigned, true, engineOwned)
			if rollbackErr != nil {
				return engineOwned, errors.New("Keenetic DNS profile setup failed and rollback was incomplete")
			}
			return engineOwned, errors.New("Keenetic rejected the Hestia DNS profile configuration")
		}
		assigned = append(assigned, name)
	}
	if err = runNDMC(ctx, "system configuration save"); err != nil {
		rollbackErr := rollbackDNSForwarder(ctx, assigned, true, engineOwned)
		if rollbackErr != nil {
			return engineOwned, errors.New("saving the Keenetic DNS profile failed and rollback was incomplete")
		}
		return engineOwned, errors.New("Keenetic DNS profile could not be saved")
	}
	return engineOwned, nil
}

// rollbackDNSForwarder removes only resources confirmed as created by the failed Hestia enable transaction.
func rollbackDNSForwarder(ctx context.Context, interfaces []string, profileCreated, engineOwned bool) error {
	var failures []error
	for _, name := range interfaces {
		failures = append(failures, runNDMC(ctx, "no dns-proxy filter assign interface profile "+name))
	}
	if profileCreated {
		failures = append(failures, runNDMC(ctx, "no dns-proxy filter profile "+hestiaDNSProfile))
	}
	if engineOwned && !otherDNSFilterSettings(ctx) {
		failures = append(failures, runNDMC(ctx, "no dns-proxy filter engine"))
	}
	failures = append(failures, runNDMC(ctx, "system configuration save"))
	if rollbackErr := errors.Join(failures...); rollbackErr != nil {
		return errors.New("DNS profile operation failed and rollback was incomplete")
	}
	return nil
}

// readDNSForwarderConfig loads and validates the local-loopback Hestia listener without exposing upstream settings.
func readDNSForwarderConfig(path string) (dnsForwarderConfig, error) {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() || info.Mode().Perm()&0o077 != 0 || info.Size() > 64<<10 {
		return dnsForwarderConfig{}, errors.New("Hestia DNS configuration is unavailable or has unsafe permissions")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
	if err != nil {
		return dnsForwarderConfig{}, errors.New("Hestia DNS configuration is unavailable")
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil || !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return dnsForwarderConfig{}, errors.New("Hestia DNS configuration changed while opening")
	}
	owner, ok := openedInfo.Sys().(*syscall.Stat_t)
	if !ok || owner.Uid != 0 {
		return dnsForwarderConfig{}, errors.New("Hestia DNS configuration must be owned by root")
	}
	var config dnsForwarderConfig
	decoder := json.NewDecoder(io.LimitReader(file, 64<<10))
	decoder.DisallowUnknownFields()
	if err = decoder.Decode(&config); err != nil {
		return dnsForwarderConfig{}, errors.New("Hestia DNS configuration is invalid")
	}
	if err = decoder.Decode(new(json.RawMessage)); !errors.Is(err, io.EOF) {
		return dnsForwarderConfig{}, errors.New("Hestia DNS configuration contains trailing data")
	}
	listen, err := netip.ParseAddrPort(config.Listen)
	peer, peerErr := netip.ParseAddr(config.Router)
	if err != nil || peerErr != nil || !listen.Addr().Is4() || !listen.Addr().IsLoopback() || !peer.Is4() || !peer.IsLoopback() || listen.Port() < 1024 {
		return dnsForwarderConfig{}, errors.New("Hestia DNS listener and peer must use loopback; listener port must be at least 1024")
	}
	return config, nil
}

// checkDNSForwarderListener requires the configured Hestia TCP listener to accept a local readiness connection.
func checkDNSForwarderListener(ctx context.Context, config dnsForwarderConfig) error {
	address, _ := netip.ParseAddrPort(config.Listen)
	dialer := net.Dialer{Timeout: time.Second}
	conn, err := dialer.DialContext(ctx, "tcp4", address.String())
	if err != nil {
		return errors.New("Hestia DNS listener is not ready on the configured loopback address")
	}
	return conn.Close()
}

// readDNSForwarderProfile reads only the router's DNS-proxy block and validates Hestia ownership metadata.
func readDNSForwarderProfile(ctx context.Context) (dnsForwarderProfile, error) {
	lines, err := readDNSProxyLines(ctx)
	if err != nil {
		return dnsForwarderProfile{}, err
	}
	profile := dnsForwarderProfile{}
	for _, line := range lines {
		if line == "filter profile "+hestiaDNSProfile || strings.HasPrefix(line, "filter profile "+hestiaDNSProfile+" ") {
			profile.Present = true
		}
		if line == "filter engine "+hestiaEngineProfileName {
			profile.EngineOwned = false
		}
		if strings.HasPrefix(line, "filter assign interface profile ") {
			fields := strings.Fields(line)
			if len(fields) == 6 && fields[5] == hestiaDNSProfile {
				profile.Interfaces = append(profile.Interfaces, fields[4])
			}
		}
	}
	if !profile.Present {
		return profile, nil
	}
	profile.Listen, profile.Exact, profile.EngineOwned, profile.ExpectedInterfaces = parseOwnedDNSProfile(lines)
	profile.Exact = profile.Exact && slices.Equal(profile.Interfaces, profile.ExpectedInterfaces)
	return profile, nil
}

// parseOwnedDNSProfile accepts one exact Hestia profile and returns its upstream, ownership, and saved interfaces.
func parseOwnedDNSProfile(lines []string) (netip.AddrPort, bool, bool, []string) {
	var upstreams []string
	var description string
	var profileLines int
	var enginePresent bool
	for _, line := range lines {
		if strings.HasPrefix(line, "filter profile "+hestiaDNSProfile+" dns53 upstream ") {
			upstreams = append(upstreams, strings.TrimPrefix(line, "filter profile "+hestiaDNSProfile+" dns53 upstream "))
		}
		if strings.HasPrefix(line, "filter profile "+hestiaDNSProfile+" description ") {
			description = strings.Trim(strings.TrimPrefix(line, "filter profile "+hestiaDNSProfile+" description "), `"`)
		}
		if strings.HasPrefix(line, "filter profile "+hestiaDNSProfile+" ") {
			profileLines++
		}
		if line == "filter engine "+hestiaEngineProfileName {
			enginePresent = true
		}
	}
	expectedInterfaces, ownedEngine, descriptionOK := parseEngineOwnershipDescription(description)
	if !descriptionOK || profileLines != 2 || len(upstreams) != 1 || !enginePresent {
		return netip.AddrPort{}, false, ownedEngine, expectedInterfaces
	}
	upstream, err := netip.ParseAddrPort(upstreams[0])
	if err != nil || !upstream.Addr().Is4() || !upstream.Addr().IsLoopback() || upstream.Port() < 1024 {
		return netip.AddrPort{}, false, ownedEngine, expectedInterfaces
	}
	return upstream, true, ownedEngine, expectedInterfaces
}

// readDNSProxyLines returns normalized lines from the DNS-proxy configuration without retaining other router settings.
func readDNSProxyLines(ctx context.Context) ([]string, error) {
	config, err := runNDMCOutput(ctx, "show running-config")
	if err != nil {
		return nil, errors.New("cannot read Keenetic DNS-proxy configuration")
	}
	var lines []string
	inside := false
	found := false
	terminated := false
	config = terminalControlPattern.ReplaceAllString(config, "")
	scanner := bufio.NewScanner(strings.NewReader(config))
	scanner.Buffer(make([]byte, 4096), 1<<20)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "dns-proxy" {
			if found {
				return nil, errors.New("Keenetic DNS-proxy configuration block is ambiguous")
			}
			found = true
			inside = true
			continue
		}
		if !inside {
			continue
		}
		if line == "!" {
			inside = false
			terminated = true
			continue
		}
		if line != "" {
			lines = append(lines, line)
		}
	}
	if err = scanner.Err(); err != nil {
		return nil, errors.New("cannot parse Keenetic DNS-proxy configuration")
	}
	if !found || !terminated || inside {
		return nil, errors.New("Keenetic DNS-proxy configuration block is missing")
	}
	return lines, nil
}

// checkInterfaceAssignments refuses to replace profiles or presets already assigned to requested LAN interfaces.
func checkInterfaceAssignments(ctx context.Context, interfaces []string) error {
	lines, err := readDNSProxyLines(ctx)
	if err != nil {
		return err
	}
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) >= 5 && fields[0] == "filter" && fields[1] == "assign" && fields[2] == "interface" && slices.Contains(interfaces, fields[4]) {
			return errors.New("a requested LAN interface already has a Keenetic DNS profile or preset")
		}
		if strings.HasPrefix(line, "filter assign host profile ") || strings.HasPrefix(line, "filter assign host preset ") {
			return errors.New("Keenetic has per-device DNS overrides; refusing to claim all clients use Hestia")
		}
	}
	return nil
}

// ensureInterfacesExist rejects interface names that are not present in the router's current interface inventory.
func ensureInterfacesExist(ctx context.Context, interfaces []string) error {
	output, err := runNDMCOutput(ctx, "show interface")
	if err != nil {
		return errors.New("cannot read Keenetic interface inventory")
	}
	known := make(map[string]struct{})
	output = terminalControlPattern.ReplaceAllString(output, "")
	for _, line := range strings.Split(output, "\n") {
		start := strings.Index(line, `Interface, name = "`)
		if start < 0 {
			continue
		}
		name := strings.TrimSuffix(line[start+len(`Interface, name = "`):], `"`)
		known[name] = struct{}{}
	}
	for _, name := range interfaces {
		if _, ok := known[name]; !ok {
			return fmt.Errorf("Keenetic interface %q does not exist", name)
		}
	}
	return nil
}

// hasDNSFilterEngine detects a configured engine other than the Hestia-compatible interceptor engine.
func hasDNSFilterEngine(lines []string) bool {
	return slices.ContainsFunc(lines, func(line string) bool {
		return strings.HasPrefix(line, "filter engine ")
	})
}

// hasOtherDNSFilterSettings detects profiles or assignments that could become active when Hestia enables the global engine.
func hasOtherDNSFilterSettings(lines []string) bool {
	for _, line := range lines {
		if strings.HasPrefix(line, "filter profile ") || strings.HasPrefix(line, "filter assign ") {
			return true
		}
	}
	return false
}

// otherDNSFilterSettings reports whether filter configuration would make removing the Hestia-owned engine unsafe.
func otherDNSFilterSettings(ctx context.Context) bool {
	lines, err := readDNSProxyLines(ctx)
	if err != nil {
		return true
	}
	return hasOtherDNSFilterSettings(lines)
}

// writeDNSForwarderStatus prints a compact status without exposing unrelated router configuration.
func writeDNSForwarderStatus(writer io.Writer, profile dnsForwarderProfile) error {
	if !profile.Present {
		_, err := fmt.Fprintln(writer, "Hestia DNS profile is not configured")
		return err
	}
	if !profile.Exact {
		_, err := fmt.Fprintln(writer, "Hestia DNS profile has changed or is not owned by Hestia")
		return err
	}
	_, err := fmt.Fprintf(writer, "Hestia DNS profile enabled: upstream=%s interfaces=%s\n", profile.Listen, strings.Join(profile.Interfaces, ","))
	return err
}

// engineOwnershipDescription stores the managed interface set and whether Hestia enabled the global filter engine.
func engineOwnershipDescription(owned bool, interfaces []string) string {
	engine := "shared"
	if owned {
		engine = "owned"
	}
	return hestiaDNSProfileLabel + " interfaces=" + strings.Join(interfaces, ",") + " engine=" + engine
}

// parseEngineOwnershipDescription validates Hestia's marker and extracts the exact interface assignments it owns.
func parseEngineOwnershipDescription(description string) ([]string, bool, bool) {
	fields := strings.Fields(description)
	if len(fields) != 6 || strings.Join(fields[:4], " ") != hestiaDNSProfileLabel {
		return nil, false, false
	}
	interfacesField := strings.TrimPrefix(fields[4], "interfaces=")
	if interfacesField == fields[4] || interfacesField == "" {
		return nil, false, false
	}
	engineField := strings.TrimPrefix(fields[5], "engine=")
	if engineField != "owned" && engineField != "shared" {
		return nil, false, false
	}
	interfaces := strings.Split(interfacesField, ",")
	for i, name := range interfaces {
		if !dnsInterfacePattern.MatchString(name) || strings.ContainsAny(name, "\"' `") || i > 0 && name <= interfaces[i-1] {
			return nil, false, false
		}
	}
	return interfaces, engineField == "owned", true
}

// runNDMC runs one fixed Keenetic CLI command and discards output containing unrelated router settings.
func runNDMC(ctx context.Context, command string) error {
	_, err := runNDMCOutput(ctx, command)
	return err
}

// runNDMCOutput executes the fixed Keenetic CLI with a bounded context and returns its output only to local parsers.
func runNDMCOutput(ctx context.Context, command string) (string, error) {
	commandCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	process := exec.CommandContext(commandCtx, keeneticNDMCPath, "-c", command)
	output, err := process.CombinedOutput()
	if err != nil {
		return "", errors.New("Keenetic command failed")
	}
	return string(output), nil
}
