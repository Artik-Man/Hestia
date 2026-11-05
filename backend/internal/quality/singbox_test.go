package quality

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// TestRealSingBoxLoopback checks Hestia's actual SOCKS code through sing-box with only local destinations.
func TestRealSingBoxLoopback(t *testing.T) {
	binary := os.Getenv("HESTIA_QUALITY_TEST_SING_BOX")
	if binary == "" {
		t.Skip("set HESTIA_QUALITY_TEST_SING_BOX to run the real sing-box loopback integration")
	}
	device := "lo"
	if runtime.GOOS == "darwin" {
		device = "lo0"
	}
	reserve, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	proxy := reserve.Addr().(*net.TCPAddr)
	reserve.Close()
	tcp, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer tcp.Close()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	dir := t.TempDir()
	config := fmt.Sprintf(`{
		"inbounds": [{
			"type": "socks", "tag": "_quality-fi1", "listen": "127.0.0.1", "listen_port": %d,
			"users": [{"username":"hestia-quality","password":"local-test"}]
		}],
		"outbounds": [{"type":"direct","tag":"fi1","bind_interface": %q}],
		"route": {"rules":[{"inbound":["_quality-fi1"],"action":"route","outbound":"fi1"},{"action":"reject"}]}
	}`, proxy.Port, device)
	path := filepath.Join(dir, "backend.json")
	if err := os.WriteFile(path, []byte(config), 0600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary, "run", "-c", path)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()
	deadline := time.Now().Add(4 * time.Second)
	for {
		if c, e := net.DialTimeout("tcp", proxy.String(), 100*time.Millisecond); e == nil {
			c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("SOCKS process did not become ready")
		}
		time.Sleep(20 * time.Millisecond)
	}
	route := Path{ID: "fi1", SocksAddress: proxy.String(), SocksPassword: "local-test"}
	tcpCheck := Check{Protocol: TCP, TimeoutSeconds: 2}
	udpCheck := Check{Protocol: UDP, DNSName: "example.com", TimeoutSeconds: 2}
	gotTCP := make(chan error, 1)
	go func() {
		c, e := tcp.Accept()
		if e == nil {
			c.Close()
		}
		gotTCP <- e
	}()
	if got := probe(context.Background(), route, tcpCheck, tcp.Addr().String()); got != success {
		t.Fatalf("TCP success: %v", got)
	}
	select {
	case e := <-gotTCP:
		if e != nil {
			t.Fatal(e)
		}
	case <-time.After(time.Second):
		t.Fatal("target TCP server never accepted")
	}
	t.Log("authenticated TCP: real target accepted")
	tcp.Close()
	if got := probe(context.Background(), route, tcpCheck, tcp.Addr().String()); got != failure {
		t.Fatalf("TCP refusal recorded as outcome %v; want failure (%v)", got, failure)
	}
	t.Log("closed target TCP port: completed failure")
	gotUDP := make(chan error, 1)
	go func() {
		buf := make([]byte, 512)
		n, peer, e := udp.ReadFromUDP(buf)
		if e == nil && n >= 12 {
			buf[2] |= 0x80
			_, e = udp.WriteToUDP(buf[:n], peer)
		} else if e == nil {
			e = fmt.Errorf("short UDP DNS query")
		}
		gotUDP <- e
	}()
	if got := probe(context.Background(), route, udpCheck, udp.LocalAddr().String()); got != success {
		t.Fatalf("UDP DNS round-trip outcome %v", got)
	}
	if err := <-gotUDP; err != nil {
		t.Fatal(err)
	}
	t.Log("authenticated UDP ASSOCIATE: DNS target received query and matching answer reached probe")
	t.Run("HTTP3", func(t *testing.T) { verifyHTTP3Path(t, route) })
	route.SocksPassword = "wrong"
	if got := probe(context.Background(), route, udpCheck, udp.LocalAddr().String()); got != localError {
		t.Fatalf("auth failure recorded as %v", got)
	}
	t.Log("wrong password: local measurement error")
}
