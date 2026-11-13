import test from "node:test";
import assert from "node:assert/strict";
import {
  validExitId,
  validHost,
  validSubnet,
} from "../src/core/components/profile-draft/profile-validation.ts";
import {
  isUnderlayCandidate,
  isUserSelectableUnderlay,
} from "../src/core/models/awg-connection.ts";

test("exit identifiers reject reserved or path characters in any position", () => {
  for (const id of [
    "/",
    "#wan",
    "wan/",
    "v?p",
    "v\\p",
    " fi",
    "ru ",
    ".",
    "..",
    "deny",
  ]) {
    assert.equal(validExitId(id), false, id);
  }
  assert.equal(validExitId("fi+2"), true);
});

test("platform input channels are hidden from underlay choices without rejecting saved IDs", () => {
  assert.equal(
    isUserSelectableUnderlay("wg-keenetic", {
      id: "wg-keenetic",
      type: "wireguard",
      role: "input",
    }),
    false,
  );
  assert.equal(isUserSelectableUnderlay("wg-keenetic", undefined), false);
  assert.equal(isUserSelectableUnderlay("keenetic-opkgtun", undefined), false);
  assert.equal(
    isUserSelectableUnderlay("keenetic-direct", {
      id: "keenetic-direct",
      type: "direct",
      role: "output",
    }),
    true,
  );
  assert.equal(
    isUserSelectableUnderlay("other-vpn", {
      id: "other-vpn",
      type: "amneziawg",
    }),
    true,
  );
  assert.equal(isUserSelectableUnderlay("deleted-vpn", undefined), true);
});

test("IPv6 hosts require matching brackets and cannot include a port", () => {
  for (const value of ["[::1", "::1]", "[::1]:443"]) {
    assert.equal(validHost(value), false, value);
  }
  assert.equal(validHost("::1"), true);
  assert.equal(validHost("[2001:db8::2]"), true);
  assert.equal(validSubnet("::1/129"), false);
});

/** Rejects malformed administrative flags instead of allowing a disabled value to become truthy. */
test("connection catalog validates explicit administrative states", () => {
  const candidate = { id: "saved-wg", name: "Saved WG", type: "wireguard" };
  assert.ok(isUnderlayCandidate(candidate));
  for (const enabled of [true, false])
    assert.ok(isUnderlayCandidate({ ...candidate, enabled }));
  for (const enabled of [null, 0, "false"])
    assert.equal(isUnderlayCandidate({ ...candidate, enabled }), false);
});
