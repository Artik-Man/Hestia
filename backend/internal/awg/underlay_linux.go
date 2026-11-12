//go:build linux

package awg

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"sync"
	"time"
)

// candidateSamples measures delay through each actual selected sing-box exit; transport errors and malformed responses count as loss.
func candidateSamples(ctx context.Context, client *http.Client, ids []string) []bool {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Second)
	defer cancel()
	result := make([]bool, len(ids))
	var workers sync.WaitGroup
	for i, id := range ids {
		workers.Add(1)
		go func() {
			defer workers.Done()
			endpoint := "http://127.0.0.1:9090/proxies/" + url.PathEscape(id) + "/delay?timeout=1500&url=" + url.QueryEscape("https://ya.ru/")
			request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
			if err != nil {
				return
			}
			response, err := client.Do(request)
			if err != nil {
				return
			}
			defer response.Body.Close()
			var status struct {
				Delay *int `json:"delay"`
			}
			if response.StatusCode == http.StatusOK && json.NewDecoder(io.LimitReader(response.Body, 4096)).Decode(&status) == nil &&
				status.Delay != nil && *status.Delay >= 0 && *status.Delay <= 1500 {
				result[i] = true
			}
		}()
	}
	workers.Wait()
	return result
}

// superviseManualTransport probes candidates, routes encrypted transport and publishes readiness only after actual inner DNS and HTTPS succeed.
func (p RoutePolicy) superviseManualTransport(ctx context.Context, relay *underlayRelay, metadata Metadata, dnsServers []string, readyPath, healthPath string) error {
	if err := p.ActivateIPv4(ctx); err != nil {
		return err
	}
	quality := make([]pathQuality, len(metadata.Underlays))
	client := &http.Client{Transport: &http.Transport{Proxy: nil}, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	defer client.CloseIdleConnections()
	defer os.Remove(readyPath)
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()
	ready, working := false, false
	failedInner, trialGood, trialMiss := 0, 0, 0
	for {
		for i, ok := range candidateSamples(ctx, client, metadata.Underlays) {
			quality[i].observe(ok)
		}
		if ctx.Err() != nil {
			return nil
		}
		now := time.Now()
		next := preferredUnderlay(quality, now)
		if !working {
			next = activationUnderlay(quality, now)
		}
		trial := -1
		if working && relay.index >= 0 && next >= 0 && next < relay.index && quality[relay.index].healthy {
			trial = next
			next = relay.index
		}
		if trial != relay.trialIndex {
			trialGood, trialMiss = 0, 0
			if err := relay.probePath(trial); err != nil {
				return err
			}
		}
		if next != relay.index {
			working = false
			failedInner = 0
			if err := relay.selectPath(next); err != nil {
				return err
			}
		}
		healthy := false
		if next >= 0 {
			confirmed := false
			if trial >= 0 {
				confirmed = p.challengePreferred(ctx, relay, metadata.DNSIPv4)
			}
			probe, cancel := context.WithTimeout(ctx, 3*time.Second)
			_, probeErr := p.probeMarkedEgress(probe, dnsServers)
			healthy = probeErr == nil
			cancel()
			if !healthy {
				quality[next].peerSuccess = 0
				failedInner++
				if failedInner >= 2 {
					working = false
					quality[next].quarantine(time.Now())
					_ = relay.probePath(-1)
					_ = relay.selectPath(-1)
					failedInner = 0
				}
			} else {
				failedInner = 0
				working = true
				quality[next].confirmPeer()
				if trial >= 0 {
					if confirmed {
						trialGood++
					} else {
						trialMiss++
					}
					if trialGood >= 3 && relay.trialReplies() > 0 {
						relay.promoteTrial()
						next = trial
						quality[trial].retryAfter = time.Time{}
						quality[trial].backoff = 0
					} else if trialGood+trialMiss >= 9 {
						quality[trial].quarantine(time.Now())
						_ = relay.probePath(-1)
					}
				}
			}
		}
		if healthy {
			if err := writeHealthMarker(healthPath, metadata.ID, metadata.Underlays[next]); err != nil {
				return err
			}
			if !ready {
				if err := writeReadyMarker(readyPath); err != nil {
					return err
				}
				ready = true
			}
		} else {
			if ready {
				_ = os.Remove(readyPath)
				ready = false
			}
			_ = os.Remove(healthPath)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

// challengePreferred sends three marked EDNS queries. The relay diverts only the last ciphertext in the randomized length sequence.
// A matching answer to the final independent transaction and a WireGuard-authenticated witness are required before promotion.
func (p RoutePolicy) challengePreferred(ctx context.Context, r *underlayRelay, dns string) bool {
	dev, err := net.InterfaceByName(p.device)
	if err != nil || dev.MTU < 320 {
		return false
	}
	conn, err := p.boundDialer().DialContext(ctx, "udp4", net.JoinHostPort(dns, "53"))
	if err != nil {
		return false
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(1500 * time.Millisecond))
	var entropy [9]byte
	if _, err = rand.Read(entropy[:]); err != nil {
		return false
	}
	var packets [3][]byte
	signature := make([]int, 3)
	blocks := min(dev.MTU, 1280) / 16
	for i := range packets {
		// Disjoint bands prevent an earlier primer or its retransmission from matching the final query.
		length := (blocks - (2-i)*5 - int(entropy[i]%5)) * 16
		if r.variablePadding {
			// The pinned daemon caps random additions at the largest observed datagram.
			// Full-size inner packets exhaust that window for peers with matching MTUs.
			length = dev.MTU
		}
		packet := make([]byte, length-28)
		copy(packet, []byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 1, 2, 'y', 'a', 2, 'r', 'u', 0, 0, 1, 0, 1, 0, 0, 41, 5, 0, 0, 0, 0, 0, 0, 0, 0, 12, 0, 0})
		copy(packet[:2], entropy[3+2*i:5+2*i])
		packet[0] = packet[0]&0x3f | byte(i)<<6
		binary.BigEndian.PutUint16(packet[32:34], uint16(len(packet)-34))
		binary.BigEndian.PutUint16(packet[36:38], uint16(len(packet)-38))
		packets[i] = packet
		signature[i] = length + 32 + r.prefixBytes
	}
	r.mu.Lock()
	r.signature = signature
	r.proofBudget = 3
	r.mu.Unlock()
	defer func() { r.mu.Lock(); r.signature = nil; r.mu.Unlock() }()
	var answer [2048]byte
	for i, packet := range packets {
		r.mu.Lock()
		r.sampleUntil = time.Now().Add(75 * time.Millisecond)
		r.mu.Unlock()
		if _, err = conn.Write(packet); err != nil {
			return false
		}
		// Wait for each primer to finish returning through the backup. Concurrent primers can roam
		// the remote peer back to the backup while it is answering the exclusive candidate challenge.
		for {
			n, err := conn.Read(answer[:])
			if err != nil {
				return false
			}
			if n >= 12 && answer[0] == packet[0] && answer[1] == packet[1] && answer[2]&0x80 != 0 && answer[3]&15 == 0 && binary.BigEndian.Uint16(answer[6:8]) > 0 {
				break
			}
		}
		r.mu.Lock()
		matched := len(r.signature) == len(packets)-1-i
		r.sampleUntil = time.Time{}
		r.mu.Unlock()
		if !matched {
			return false
		}
	}
	return true
}
