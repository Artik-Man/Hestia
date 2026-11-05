import test from "node:test";
import assert from "node:assert/strict";
import {
  isPublicCertificateBundle,
  parseClientProfile,
} from "../src/core/components/hysteria2-editor/client-profile.ts";

test("import preserves quoted credentials and requests the referenced certificate", () => {
  const parsed = parseClientProfile(
    'server: "[2001:db8::1]:4443"\nauth: "u:p#ss"\ntls: { ca: ./trust/service.pem, sni: vpn.example }\nsocks5: { listen: localhost:1080 }',
  );
  assert.deepEqual(parsed, {
    server: "2001:db8::1",
    port: 4443,
    password: "u:p#ss",
    serverName: "vpn.example",
    ca: "./trust/service.pem",
    ignoresSocks: true,
  });
});

test("incompatible profiles report the relevant option without including credential values", () => {
  for (const [fragment, field] of [
    ["tls: { insecure: true }", "tls.insecure"],
    ["obfs: {type: salamander}", "obfs"],
    ["transport: {udp: {hopInterval: 10s}}", "transport"],
    ["server: vpn.example:20001-20100", "server"],
    ["server: vpn.example:443,445", "server"],
  ]) {
    const server = fragment.startsWith("server:")
      ? ""
      : "server: vpn.example:443\n";
    assert.throws(
      () => parseClientProfile(server + "auth: confidential\n" + fragment),
      (error) =>
        error.message.includes(field) &&
        !error.message.includes("confidential"),
    );
  }
  assert.throws(
    () =>
      parseClientProfile(
        "server: vpn.example:443\nauth: secret1\nauth: secret2",
      ),
    (error) => !error.message.includes("secret"),
  );
});

test("malformed repeated PEM envelopes are rejected within bounded processing time", () => {
  const cert =
    "-----BEGIN CERTIFICATE-----\nYWJj\n-----END CERTIFICATE-----    \n";
  const start = performance.now();
  assert.equal(isPublicCertificateBundle(cert.repeat(100)), true);
  assert.equal(isPublicCertificateBundle(cert.repeat(100) + "!"), false);
  assert.ok(performance.now() - start < 500);
});

test("host input normalizes bracketed IPv6 while preserving the API's absolute DNS names", async () => {
  const { normalizeHysteriaHost } =
    await import("../src/core/models/hysteria2-host.ts");
  for (const value of ["vpn.example.", "203.0.113.2", "::ffff:192.0.2.1"])
    assert.equal(normalizeHysteriaHost(value), value);
  assert.equal(normalizeHysteriaHost("[2001:db8::1]"), "2001:db8::1");
  for (const value of ["192.0.2.999", "127.1", "192.00.2.1", "::1%lo"])
    assert.equal(normalizeHysteriaHost(value), null);
});
