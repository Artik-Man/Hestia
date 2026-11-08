package awgruntime

import (
	"context"
	"os/exec"
	"reflect"
	"testing"
)

// TestRuntimeOperationsPreserveCommands verifies interface isolation and peer arguments at the process boundary.
func TestRuntimeOperationsPreserveCommands(t *testing.T) {
	var gotName string
	var gotArgs []string
	driver := Linux{command: func(ctx context.Context, name string, args ...string) *exec.Cmd {
		gotName = name
		gotArgs = append([]string(nil), args...)
		return exec.CommandContext(ctx, "/usr/bin/true")
	}}
	cases := []struct {
		name string
		args []string
		run  func() error
	}{
		{"/usr/sbin/ip", []string{"addr", "add", "10.0.0.2/32", "dev", "hawg0", "noprefixroute"}, func() error { return driver.Address(context.Background(), "hawg0", "10.0.0.2/32") }},
		{"/usr/sbin/ip", []string{"link", "set", "dev", "hawg0", "up"}, func() error { return driver.Activate(context.Background(), "hawg0") }},
		{"/usr/sbin/ip", []string{"link", "delete", "dev", "hawg0"}, func() error { return driver.Delete(context.Background(), "hawg0") }},
		{"/usr/local/bin/awg", []string{"setconf", "hawg0", "private/profile"}, func() error { return driver.Configure(context.Background(), "hawg0", "private/profile") }},
		{"/usr/local/bin/awg", []string{"set", "hawg0", "peer", "peer", "persistent-keepalive", "1"}, func() error { return driver.Keepalive(context.Background(), "hawg0", "peer", "1") }},
		{"/usr/local/bin/awg", []string{"set", "hawg0", "peer", "peer", "endpoint", "127.0.0.1:123"}, func() error { return driver.Endpoint(context.Background(), "hawg0", "peer", "127.0.0.1:123") }},
	}
	for _, c := range cases {
		if err := c.run(); err != nil {
			t.Fatal(err)
		}
		if gotName != c.name || !reflect.DeepEqual(gotArgs, c.args) {
			t.Fatalf("got %s %v want %s %v", gotName, gotArgs, c.name, c.args)
		}
	}
	for query, field := range map[Query]string{PublicKey: "public-key", LatestHandshakes: "latest-handshakes", ListenPort: "listen-port", Endpoints: "endpoints", Transfer: "transfer"} {
		if _, err := driver.Observe(context.Background(), query, "hawg0"); err != nil {
			t.Fatal(err)
		}
		if gotName != "/usr/local/bin/awg" || !reflect.DeepEqual(gotArgs, []string{"show", "hawg0", field}) {
			t.Fatal(gotName, gotArgs)
		}
	}
}

// TestDaemonStartReturnsWorkingCleanup verifies foreground startup, UAPI readiness and process reaping.
func TestDaemonStartReturnsWorkingCleanup(t *testing.T) {
	var child *exec.Cmd
	driver := Linux{command: func(ctx context.Context, name string, args ...string) *exec.Cmd {
		if name == "/usr/local/lib/hestia/amneziawg-go" {
			if !reflect.DeepEqual(args, []string{"-f", "hawg0"}) {
				t.Fatal(args)
			}
			child = exec.CommandContext(ctx, "/bin/sleep", "60")
			return child
		}
		if name != "/usr/local/bin/awg" || !reflect.DeepEqual(args, []string{"show", "hawg0", "public-key"}) {
			t.Fatal(name, args)
		}
		return exec.CommandContext(ctx, "/usr/bin/true")
	}}
	read, stop, err := driver.Start(context.Background(), "hawg0")
	if err != nil {
		t.Fatal(err)
	}
	if read == nil || stop == nil {
		t.Fatal("missing lifetime handles")
	}
	stop()
	if child.ProcessState == nil {
		t.Fatal("process not reaped")
	}
}
