import test from "node:test";
import assert from "node:assert/strict";
import {
  validExitId,
  validHost,
  validSubnet,
} from "../src/profile-validation.ts";

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

test("IPv6 hosts require matching brackets and cannot include a port", () => {
  for (const value of ["[::1", "::1]", "[::1]:443"]) {
    assert.equal(validHost(value), false, value);
  }
  assert.equal(validHost("::1"), true);
  assert.equal(validHost("[2001:db8::2]"), true);
  assert.equal(validSubnet("::1/129"), false);
});
