package dnsresolver

import (
	"context"
	"testing"

	"golang.org/x/net/dns/dnsmessage"
)

// TestInvalidWireNamesDoNotAlias verifies non-ASCII questions cannot be folded into unrelated ASCII cache keys.
func TestInvalidWireNamesDoNotAlias(t *testing.T) {
	req, err := buildQuery("K.example", dnsmessage.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = parseQuestion(req); err == nil {
		t.Fatal("accepted wire Unicode Kelvin sign as an ASCII hostname")
	}
}

// TestUnrelatedRepliesNeverInvalidate verifies unrelated answers, referrals, CNAME loops and unrelated zones fail closed.
func TestUnrelatedRepliesNeverInvalidate(t *testing.T) {
	req, err := buildQuery("valid.example", dnsmessage.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	q, err := parseQuestion(req)
	if err != nil {
		t.Fatal(err)
	}
	item := q.message.Questions[0]
	wrong := dnsmessage.MustNewName("elsewhere.invalid.")
	wrongAnswer := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: wrong, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{}}
	ns := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: item.Name, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.NSResource{NS: item.Name}}
	loop := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: item.Name, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.CNAMEResource{CNAME: item.Name}}
	soa := dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: wrong, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.SOAResource{NS: wrong, MBox: wrong, MinTTL: 60}}
	for _, m := range []dnsmessage.Message{
		{Answers: []dnsmessage.Resource{wrongAnswer}},
		{Answers: []dnsmessage.Resource{loop, {Header: dnsmessage.ResourceHeader{Name: item.Name, Class: dnsmessage.ClassINET, TTL: 60}, Body: &dnsmessage.AResource{}}}},
		{Answers: []dnsmessage.Resource{loop}},
		{Authorities: []dnsmessage.Resource{ns}},
		{Authorities: []dnsmessage.Resource{soa}},
		{},
	} {
		m.Header = dnsmessage.Header{ID: 41, Response: true, RecursionAvailable: true, Authoritative: len(m.Answers) > 0 || len(m.Authorities) > 0}
		m.Questions = q.message.Questions
		p, err := m.Pack()
		if err != nil {
			t.Fatal(err)
		}
		if _, err := classify(q, 41, p); err == nil {
			t.Fatalf("accepted invalid answer: %+v", m)
		}
	}
}

// TestRetainedWireIsCompact verifies that the cache does not retain full UDP buffers for tiny DNS answers.
func TestRetainedWireIsCompact(t *testing.T) {
	up := Upstream{"fixture", "resolver"}
	routes := &testRoutes{allowed: []Upstream{up}}
	routes.send = func(_ context.Context, _ Upstream, p []byte) ([]byte, error) {
		answer, err := fixtureAnswer(p, dnsmessage.RCodeSuccess, 120, 4)
		buf := make([]byte, 65535)
		copy(buf, answer)
		return buf[:len(answer)], err
	}
	r := New(testPolicy(t, nil), routes, "")
	testQuery(t, r, "small.example")
	r.mu.Lock()
	defer r.mu.Unlock()
	rec := r.cache[cacheKey{"small.example", dnsmessage.TypeA, up}]
	if len(rec.answer.packet) == 0 || cap(rec.answer.packet) > maxCachePacket {
		t.Fatalf("retained size %d, capacity %d", len(rec.answer.packet), cap(rec.answer.packet))
	}
}

// TestStaleClearsAuthentication verifies a stale wire reply cannot reuse a historic authenticated-data assertion.
func TestStaleClearsAuthentication(t *testing.T) {
	request, err := buildQuery("signed.example", dnsmessage.TypeA)
	if err != nil {
		t.Fatal(err)
	}
	q, err := parseQuestion(request)
	if err != nil {
		t.Fatal(err)
	}
	p, err := fixtureAnswer(request, dnsmessage.RCodeSuccess, 60, 8)
	if err != nil {
		t.Fatal(err)
	}
	p[3] |= 0x20
	answer, err := classify(q, q.message.ID, p)
	if err != nil {
		t.Fatal(err)
	}
	if answer.reply(q, 0, false)[3]&0x20 == 0 || answer.reply(q, 0, true)[3]&0x20 != 0 {
		t.Fatal("unexpected authenticated-data flags")
	}
}
