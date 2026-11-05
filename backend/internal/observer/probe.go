package observer

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strconv"
	"syscall"
	"time"
)

type Status string

const (
	Received   Status = "received"
	Lost       Status = "lost"
	LocalError Status = "local_error"
)

type Probe struct {
	Token  string  `json:"token"`
	Status Status  `json:"status"`
	RTTms  float64 `json:"rtt_ms,omitempty"`
	Detail string  `json:"detail,omitempty"`
}

// measure sends one nonce through the selected interface and accepts only its exact echo.
func measure(ctx context.Context, c Connection, t Target, timeout time.Duration) Probe {
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Probe{Status: LocalError, Detail: err.Error()}
	}
	p := Probe{Token: "hestia-" + hex.EncodeToString(nonce[:])}
	parent := ctx
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	start := time.Now()
	dialer := net.Dialer{Control: bindDevice(c.Interface)}
	conn, err := dialer.DialContext(ctx, t.Protocol+"4", net.JoinHostPort(t.Address, strconv.Itoa(t.Port)))
	if err != nil {
		return failed(p, err)
	}
	defer conn.Close()
	stopClose := context.AfterFunc(parent, func() { conn.Close() })
	defer stopClose()
	deadline, _ := ctx.Deadline()
	if err = conn.SetDeadline(deadline); err != nil {
		return failed(p, err)
	}
	want := []byte(p.Token + "\n")
	n, err := conn.Write(want)
	if err != nil {
		return failed(p, err)
	}
	if n != len(want) {
		return failed(p, io.ErrShortWrite)
	}
	var got []byte
	if t.Protocol == "tcp" {
		got = make([]byte, len(want))
		_, err = io.ReadFull(conn, got)
	} else {
		got = make([]byte, len(want)+1)
		n, err = conn.Read(got)
		got = got[:n]
	}
	if err != nil {
		return failed(p, err)
	}
	if !bytes.Equal(want, got) {
		p.Status, p.Detail = Lost, "unexpected_echo"
		return p
	}
	p.Status, p.RTTms = Received, float64(time.Since(start))/float64(time.Millisecond)
	return p
}

// failed counts timeouts and remote transport failures as failed echo attempts, excluding other I/O failures as local errors.
func failed(p Probe, err error) Probe {
	var timeout net.Error
	p.Status, p.Detail = LocalError, err.Error()
	if (errors.As(err, &timeout) && timeout.Timeout()) || errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) || errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		p.Status = Lost
	}
	return p
}
