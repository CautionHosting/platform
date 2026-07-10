import assert from "node:assert/strict";
import test from "node:test";

import { findDuplicateSshKey } from "./sshKeys.js";

const existingKey = {
  public_key: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIMatchingKeyMaterial existing@example",
  fingerprint: "SHA256:existing",
  name: "laptop",
};

test("findDuplicateSshKey matches the same SSH public key before comments", () => {
  const duplicate = findDuplicateSshKey(
    "  ssh-ed25519   AAAAC3NzaC1lZDI1NTE5AAAAIMatchingKeyMaterial new-comment@example  ",
    [existingKey]
  );

  assert.equal(duplicate, existingKey);
});

test("findDuplicateSshKey ignores malformed and different keys", () => {
  assert.equal(
    findDuplicateSshKey("not-a-valid-key", [existingKey]),
    null
  );

  assert.equal(
    findDuplicateSshKey(
      "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDifferentKeyMaterial user@example",
      [existingKey]
    ),
    null
  );
});
