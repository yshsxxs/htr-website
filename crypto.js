/* 小姚聊天 加密模块 (Web Crypto API — 浏览器原生, 无外部依赖)
 * 账号密码: PBKDF2-SHA256 150000 次迭代
 * 私聊:     ECDH P-256 密钥协商 → AES-256-GCM
 * 群聊:     群口令 → PBKDF2 派生 → AES-256-GCM
 * 文件:     AES-GCM 加密后 base64 分片传输
 */
var YaoCrypto = (function () {
  var enc = new TextEncoder();
  var dec = new TextDecoder();

  function b64enc(buf) {
    var b = new Uint8Array(buf), s = "";
    for (var i = 0; i < b.length; i++) s += String.fromCharCode(b[i]);
    return btoa(s);
  }
  function b64dec(str) {
    var raw = atob(str.replace(/\s/g, "")), u = new Uint8Array(raw.length);
    for (var i = 0; i < raw.length; i++) u[i] = raw.charCodeAt(i);
    return u;
  }
  function randHex(n) {
    var a = new Uint8Array(n);
    crypto.getRandomValues(a);
    return Array.from(a).map(function (x) { return x.toString(16).padStart(2, "0"); }).join("");
  }

  /* ---------- 账号密码: PBKDF2 ---------- */
  async function hashPassword(password, saltB64, iterations) {
    iterations = iterations || 150000;
    var salt = saltB64 ? b64dec(saltB64) : crypto.getRandomValues(new Uint8Array(16));
    var baseKey = await crypto.subtle.importKey("raw", enc.encode(password), "PBKDF2", false, ["deriveBits"]);
    var bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt: salt, iterations: iterations, hash: "SHA-256" }, baseKey, 256);
    return { hash: b64enc(bits), salt: b64enc(salt), iter: iterations };
  }
  async function verifyPassword(password, hashB64, saltB64, iterations) {
    var r = await hashPassword(password, saltB64, iterations);
    return r.hash === hashB64;
  }

  /* ---------- 身份密钥对: ECDH P-256 ---------- */
  async function genKeyPair() {
    var kp = await crypto.subtle.generateKey({ name: "ECDH", namedCurve: "P-256" }, true, ["deriveKey", "deriveBits"]);
    var priv = await crypto.subtle.exportKey("jwk", kp.privateKey);
    var pub = await crypto.subtle.exportKey("jwk", kp.publicKey);
    return { priv: priv, pub: pub };
  }
  /* 用密码派生的密钥加密私钥 (本地保存, 防他人拿到设备) */
  async function wrapPrivateKey(privJwk, password, saltB64) {
    var h = await hashPassword(password, saltB64);
    var kek = await crypto.subtle.importKey("raw", b64dec(h.hash), "AES-GCM", false, ["encrypt", "decrypt"]);
    var iv = crypto.getRandomValues(new Uint8Array(12));
    var ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, kek, enc.encode(JSON.stringify(privJwk)));
    return b64enc(iv) + ":" + b64enc(ct);
  }
  async function unwrapPrivateKey(wrapped, password, saltB64) {
    try {
      var h = await hashPassword(password, saltB64);
      var kek = await crypto.subtle.importKey("raw", b64dec(h.hash), "AES-GCM", false, ["encrypt", "decrypt"]);
      var parts = wrapped.split(":");
      var pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: b64dec(parts[0]) }, kek, b64dec(parts[1]));
      return JSON.parse(dec.decode(pt));
    } catch (e) { return null; }
  }
  async function importPrivate(jwk) {
    return crypto.subtle.importKey("jwk", jwk, { name: "ECDH", namedCurve: "P-256" }, false, ["deriveKey", "deriveBits"]);
  }
  async function importPublic(jwk) {
    return crypto.subtle.importKey("jwk", jwk, { name: "ECDH", namedCurve: "P-256" }, false, []);
  }
  /* ECDH 协商 → AES-256-GCM 会话密钥 (私聊) */
  async function sharedKey(myPrivJwk, theirPubJwk) {
    var priv = await importPrivate(myPrivJwk);
    var pub = await importPublic(theirPubJwk);
    return crypto.subtle.deriveKey({ name: "ECDH", public: pub }, priv,
      { name: "AES-GCM", length: 256 }, false, ["encrypt", "decrypt"]);
  }
  /* 群口令 → AES 密钥 (salt 固定为群 id, 成员输同一口令即可互通) */
  async function groupKey(passphrase, groupId, iterations) {
    var salt = enc.encode("YaoChat-Group:" + (groupId || "default"));
    var baseKey = await crypto.subtle.importKey("raw", enc.encode(passphrase), "PBKDF2", false, ["deriveBits"]);
    var bits = await crypto.subtle.deriveBits(
      { name: "PBKDF2", salt: salt, iterations: iterations || 120000, hash: "SHA-256" }, baseKey, 256);
    return crypto.subtle.importKey("raw", bits, "AES-GCM", false, ["encrypt", "decrypt"]);
  }

  /* ---------- 消息加解密 (输出 "iv:密文" base64) ---------- */
  async function encrypt(key, plaintext) {
    var iv = crypto.getRandomValues(new Uint8Array(12));
    var ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, key, enc.encode(plaintext));
    return b64enc(iv) + ":" + b64enc(ct);
  }
  async function decrypt(key, payload) {
    try {
      var i = payload.indexOf(":");
      var iv = b64dec(payload.slice(0, i)), ct = b64dec(payload.slice(i + 1));
      var pt = await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, ct);
      return dec.decode(pt);
    } catch (e) { return null; }   // 密钥不对/被篡改 → null
  }

  /* ---------- 二进制加密 (文件传输) ---------- */
  async function encryptBytes(key, bytes) {
    var iv = crypto.getRandomValues(new Uint8Array(12));
    var ct = await crypto.subtle.encrypt({ name: "AES-GCM", iv: iv }, key, bytes);
    var out = new Uint8Array(iv.length + ct.byteLength);
    out.set(iv, 0); out.set(new Uint8Array(ct), iv.length);
    return out;
  }
  async function decryptBytes(key, allBytes) {
    try {
      var iv = allBytes.slice(0, 12), ct = allBytes.slice(12);
      return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-GCM", iv: iv }, key, ct));
    } catch (e) { return null; }
  }

  /* ---------- 分片 (MQTT 单条消息有上限) ---------- */
  function chunkB64(b64, size) {
    size = size || 48000;
    var out = [];
    for (var i = 0; i < b64.length; i += size) out.push(b64.substr(i, size));
    return out;
  }

  return {
    hashPassword: hashPassword, verifyPassword: verifyPassword,
    genKeyPair: genKeyPair, wrapPrivateKey: wrapPrivateKey, unwrapPrivateKey: unwrapPrivateKey,
    sharedKey: sharedKey, groupKey: groupKey,
    encrypt: encrypt, decrypt: decrypt,
    encryptBytes: encryptBytes, decryptBytes: decryptBytes,
    chunkB64: chunkB64, randHex: randHex,
    b64enc: b64enc, b64dec: b64dec
  };
})();

if (typeof module !== "undefined") { module.exports = YaoCrypto; }
