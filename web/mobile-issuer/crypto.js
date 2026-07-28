const encoder = new TextEncoder();
const BDKEY_AAD = encoder.encode("banana-desktop-bdkey-v1");
const BDKEY_FIELDS = [
  "cipher",
  "ciphertext",
  "kdf",
  "key_id",
  "product",
  "public_key",
  "schema",
];
const PKCS8_PREFIX = Uint8Array.from([
  0x30, 0x2e, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06,
  0x03, 0x2b, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20,
]);

export const PLAN_DURATIONS_SECONDS = {
  trial: 24 * 60 * 60,
  week: 7 * 24 * 60 * 60,
  month: 30 * 24 * 60 * 60,
  year: 365 * 24 * 60 * 60,
};

export function parseBdkey(value) {
  if (typeof value !== "string" || encoder.encode(value).length > 16 * 1024) {
    throw new Error("手机密钥文件无效或超过 16 KiB。");
  }
  let document;
  try {
    document = JSON.parse(value);
  } catch {
    throw new Error("手机密钥文件不是有效的 JSON。");
  }
  if (
    !isPlainObject(document)
    || JSON.stringify(Object.keys(document).sort()) !== JSON.stringify(BDKEY_FIELDS)
    || document.schema !== 1
    || document.product !== "banana-desktop-issuer"
    || !isPlainObject(document.kdf)
    || JSON.stringify(Object.keys(document.kdf).sort())
      !== JSON.stringify(["iterations", "name", "salt"])
    || document.kdf.name !== "PBKDF2-SHA256"
    || document.kdf.iterations !== 600000
    || !isPlainObject(document.cipher)
    || JSON.stringify(Object.keys(document.cipher).sort())
      !== JSON.stringify(["name", "nonce"])
    || document.cipher.name !== "AES-256-GCM"
  ) {
    throw new Error("手机密钥文件格式或版本不受支持。");
  }
  return document;
}

export async function unlockBdkey(value, password) {
  if (!password) {
    throw new Error("请输入手机密钥密码。");
  }
  const document = parseBdkey(value);
  const salt = decodeBase64url(document.kdf.salt, 16);
  const nonce = decodeBase64url(document.cipher.nonce, 12);
  const publicKeyBytes = decodeBase64url(document.public_key, 32);
  const ciphertext = decodeBase64url(document.ciphertext, 48);
  const expectedKeyId = await keyIdForPublicKey(publicKeyBytes);
  if (document.key_id !== expectedKeyId) {
    throw new Error("手机密钥文件中的公钥不匹配。");
  }

  const passwordKey = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"],
  );
  const encryptionKey = await crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      hash: "SHA-256",
      salt,
      iterations: document.kdf.iterations,
    },
    passwordKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"],
  );

  let seed;
  try {
    seed = new Uint8Array(await crypto.subtle.decrypt(
      { name: "AES-GCM", iv: nonce, additionalData: BDKEY_AAD },
      encryptionKey,
      ciphertext,
    ));
  } catch {
    throw new Error("密码错误，或手机密钥文件已损坏。");
  }
  if (seed.length !== 32) {
    throw new Error("手机密钥文件中的私钥无效。");
  }
  const pkcs8 = new Uint8Array(PKCS8_PREFIX.length + seed.length);
  pkcs8.set(PKCS8_PREFIX);
  pkcs8.set(seed, PKCS8_PREFIX.length);
  let privateKey;
  let publicKey;
  try {
    privateKey = await crypto.subtle.importKey(
      "pkcs8",
      pkcs8,
      { name: "Ed25519" },
      false,
      ["sign"],
    );
    publicKey = await crypto.subtle.importKey(
      "raw",
      publicKeyBytes,
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    const challenge = encoder.encode("banana-desktop-bdkey-check-v1");
    const signature = await crypto.subtle.sign("Ed25519", privateKey, challenge);
    if (!await crypto.subtle.verify("Ed25519", publicKey, signature, challenge)) {
      throw new Error();
    }
  } catch {
    throw new Error("此浏览器不支持 Ed25519，或密钥文件不匹配。");
  } finally {
    seed.fill(0);
    pkcs8.fill(0);
  }
  return { privateKey, publicKey, keyId: expectedKeyId };
}

export async function createActivationCode(unlockedKey, machineCode, plan, now = new Date()) {
  const normalizedMachineCode = normalizeMachineCode(machineCode);
  const duration = PLAN_DURATIONS_SECONDS[plan];
  if (!duration) {
    throw new Error("套餐无效。");
  }
  const issuedSeconds = Math.floor(now.getTime() / 1000);
  const payload = {
    schema: 1,
    product: "banana-desktop",
    key_id: unlockedKey.keyId,
    license_id: crypto.randomUUID(),
    plan,
    machine_code: normalizedMachineCode,
    issued_at: formatUtcSeconds(issuedSeconds),
    not_before: formatUtcSeconds(issuedSeconds),
    expires_at: formatUtcSeconds(issuedSeconds + duration),
  };
  const payloadBytes = encoder.encode(canonicalJson(payload));
  const signature = new Uint8Array(
    await crypto.subtle.sign("Ed25519", unlockedKey.privateKey, payloadBytes),
  );
  const payloadEncoded = encodeBase64url(payloadBytes);
  const signatureEncoded = encodeBase64url(signature);
  const code = `BD1.${payloadEncoded}.${signatureEncoded}`;
  const document = canonicalJson({
    payload: payloadEncoded,
    signature: signatureEncoded,
  });
  const sha256 = bytesToHex(
    new Uint8Array(await crypto.subtle.digest("SHA-256", encoder.encode(document))),
  );
  return { code, document, payload, sha256 };
}

export function normalizeMachineCode(value) {
  const compact = String(value).trim().toUpperCase().replaceAll("-", "");
  if (!/^[A-Z2-7]{32}$/.test(compact)) {
    throw new Error("机器码必须包含 32 个 Base32 字符。");
  }
  return compact.match(/.{4}/g).join("-");
}

function canonicalJson(value) {
  const sorted = {};
  for (const key of Object.keys(value).sort()) {
    sorted[key] = value[key];
  }
  return JSON.stringify(sorted);
}

function formatUtcSeconds(seconds) {
  return new Date(seconds * 1000).toISOString().replace(".000Z", "Z");
}

async function keyIdForPublicKey(publicKey) {
  const digest = new Uint8Array(await crypto.subtle.digest("SHA-256", publicKey));
  return `ed25519-${bytesToHex(digest).slice(0, 16)}`;
}

function decodeBase64url(value, expectedLength) {
  if (typeof value !== "string" || !/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error("手机密钥文件中的编码无效。");
  }
  const padded = value.replaceAll("-", "+").replaceAll("_", "/")
    + "=".repeat((4 - value.length % 4) % 4);
  let binary;
  try {
    binary = atob(padded);
  } catch {
    throw new Error("手机密钥文件中的编码无效。");
  }
  const decoded = Uint8Array.from(binary, (character) => character.charCodeAt(0));
  if (decoded.length !== expectedLength) {
    throw new Error("手机密钥文件中的字段长度无效。");
  }
  return decoded;
}

function encodeBase64url(value) {
  let binary = "";
  for (const byte of value) {
    binary += String.fromCharCode(byte);
  }
  return btoa(binary).replaceAll("+", "-").replaceAll("/", "_").replaceAll("=", "");
}

function bytesToHex(value) {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}
