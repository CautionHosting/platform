function parseSshPublicKeyIdentity(publicKey) {
  if (typeof publicKey !== "string") {
    return null;
  }

  const parts = publicKey.trim().split(/\s+/);
  if (parts.length < 2 || !parts[0] || !parts[1]) {
    return null;
  }

  return `${parts[0]} ${parts[1]}`;
}

export function findDuplicateSshKey(publicKey, existingKeys) {
  const identity = parseSshPublicKeyIdentity(publicKey);
  if (!identity || !Array.isArray(existingKeys)) {
    return null;
  }

  return existingKeys.find((key) => {
    return parseSshPublicKeyIdentity(key?.public_key) === identity;
  }) || null;
}
