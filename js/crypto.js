/*
 * Self-contained crypto for the hidden relay test client.
 *
 * Everything the client needs is implemented here in plain JavaScript so the
 * page works from a file:// URL with no build step, no CDN and no network
 * beyond the relay websocket itself:
 *
 *   SHA-256, HMAC-SHA256, HKDF   -- NIP-44 key derivation and event ids
 *   ChaCha20                     -- NIP-44 v2 payload encryption
 *   secp256k1 + BIP-340          -- key derivation, event signing, ECDH
 *
 * Exposed as window.HRCrypto. Not constant time; this is a test client, not a
 * wallet. Use a throwaway key.
 */
(function (global) {
  'use strict';

  // ---------------------------------------------------------------- bytes --

  function utf8ToBytes(str) {
    return new TextEncoder().encode(str);
  }

  function bytesToUtf8(bytes) {
    return new TextDecoder('utf-8', { fatal: true }).decode(bytes);
  }

  function bytesToHex(bytes) {
    let out = '';
    for (let i = 0; i < bytes.length; i++) out += bytes[i].toString(16).padStart(2, '0');
    return out;
  }

  function hexToBytes(hex) {
    if (typeof hex !== 'string' || hex.length % 2 !== 0) throw new Error('invalid hex string');
    const out = new Uint8Array(hex.length / 2);
    for (let i = 0; i < out.length; i++) {
      const byte = parseInt(hex.slice(i * 2, i * 2 + 2), 16);
      if (Number.isNaN(byte)) throw new Error('invalid hex string');
      out[i] = byte;
    }
    return out;
  }

  function concatBytes(...arrays) {
    let length = 0;
    for (const a of arrays) length += a.length;
    const out = new Uint8Array(length);
    let offset = 0;
    for (const a of arrays) {
      out.set(a, offset);
      offset += a.length;
    }
    return out;
  }

  function equalBytes(a, b) {
    if (a.length !== b.length) return false;
    let diff = 0;
    for (let i = 0; i < a.length; i++) diff |= a[i] ^ b[i];
    return diff === 0;
  }

  function randomBytes(length) {
    const out = new Uint8Array(length);
    global.crypto.getRandomValues(out);
    return out;
  }

  function bytesToBase64(bytes) {
    let binary = '';
    for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i]);
    return global.btoa(binary);
  }

  function base64ToBytes(text) {
    const binary = global.atob(text);
    const out = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) out[i] = binary.charCodeAt(i);
    return out;
  }

  function bytesToBigInt(bytes) {
    return BigInt('0x' + (bytesToHex(bytes) || '0'));
  }

  function bigIntTo32Bytes(value) {
    return hexToBytes(value.toString(16).padStart(64, '0'));
  }

  // --------------------------------------------------------------- sha256 --

  const K = new Uint32Array([
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
  ]);

  function rotr(x, n) {
    return (x >>> n) | (x << (32 - n));
  }

  function sha256(message) {
    const bitLength = message.length * 8;
    const padded = new Uint8Array((((message.length + 8) >> 6) + 1) * 64);
    padded.set(message);
    padded[message.length] = 0x80;
    const view = new DataView(padded.buffer);
    // Length as a 64 bit big endian bit count; 2^32 bits is plenty here.
    view.setUint32(padded.length - 8, Math.floor(bitLength / 0x100000000), false);
    view.setUint32(padded.length - 4, bitLength >>> 0, false);

    const h = new Uint32Array([
      0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
      0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
    ]);
    const w = new Uint32Array(64);

    for (let offset = 0; offset < padded.length; offset += 64) {
      for (let i = 0; i < 16; i++) w[i] = view.getUint32(offset + i * 4, false);
      for (let i = 16; i < 64; i++) {
        const s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >>> 3);
        const s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >>> 10);
        w[i] = (w[i - 16] + s0 + w[i - 7] + s1) | 0;
      }
      let [a, b, c, d, e, f, g, hh] = h;
      for (let i = 0; i < 64; i++) {
        const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
        const ch = (e & f) ^ (~e & g);
        const temp1 = (hh + S1 + ch + K[i] + w[i]) | 0;
        const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
        const maj = (a & b) ^ (a & c) ^ (b & c);
        const temp2 = (S0 + maj) | 0;
        hh = g; g = f; f = e;
        e = (d + temp1) | 0;
        d = c; c = b; b = a;
        a = (temp1 + temp2) | 0;
      }
      h[0] = (h[0] + a) | 0; h[1] = (h[1] + b) | 0; h[2] = (h[2] + c) | 0; h[3] = (h[3] + d) | 0;
      h[4] = (h[4] + e) | 0; h[5] = (h[5] + f) | 0; h[6] = (h[6] + g) | 0; h[7] = (h[7] + hh) | 0;
    }

    const out = new Uint8Array(32);
    const outView = new DataView(out.buffer);
    for (let i = 0; i < 8; i++) outView.setUint32(i * 4, h[i], false);
    return out;
  }

  function hmacSha256(key, message) {
    const blockSize = 64;
    let k = key.length > blockSize ? sha256(key) : key;
    if (k.length < blockSize) k = concatBytes(k, new Uint8Array(blockSize - k.length));
    const inner = new Uint8Array(blockSize);
    const outer = new Uint8Array(blockSize);
    for (let i = 0; i < blockSize; i++) {
      inner[i] = k[i] ^ 0x36;
      outer[i] = k[i] ^ 0x5c;
    }
    return sha256(concatBytes(outer, sha256(concatBytes(inner, message))));
  }

  function hkdfExtract(salt, ikm) {
    return hmacSha256(salt, ikm);
  }

  function hkdfExpand(prk, info, length) {
    let block = new Uint8Array(0);
    let okm = new Uint8Array(0);
    let counter = 1;
    while (okm.length < length) {
      block = hmacSha256(prk, concatBytes(block, info, Uint8Array.of(counter)));
      okm = concatBytes(okm, block);
      counter++;
    }
    return okm.slice(0, length);
  }

  // ------------------------------------------------------------- chacha20 --

  function chacha20(key, nonce, data) {
    if (key.length !== 32) throw new Error('ChaCha20 key must be 32 bytes');
    if (nonce.length !== 12) throw new Error('ChaCha20 nonce must be 12 bytes');
    const keyView = new DataView(key.buffer, key.byteOffset, key.byteLength);
    const nonceView = new DataView(nonce.buffer, nonce.byteOffset, nonce.byteLength);
    const state = new Uint32Array(16);
    state[0] = 0x61707865; state[1] = 0x3320646e; state[2] = 0x79622d32; state[3] = 0x6b206574;
    for (let i = 0; i < 8; i++) state[4 + i] = keyView.getUint32(i * 4, true);
    state[12] = 0; // block counter
    for (let i = 0; i < 3; i++) state[13 + i] = nonceView.getUint32(i * 4, true);

    const out = new Uint8Array(data.length);
    const block = new Uint32Array(16);
    const blockBytes = new Uint8Array(block.buffer);

    const qr = (x, a, b, c, d) => {
      x[a] = (x[a] + x[b]) | 0; x[d] ^= x[a]; x[d] = (x[d] << 16) | (x[d] >>> 16);
      x[c] = (x[c] + x[d]) | 0; x[b] ^= x[c]; x[b] = (x[b] << 12) | (x[b] >>> 20);
      x[a] = (x[a] + x[b]) | 0; x[d] ^= x[a]; x[d] = (x[d] << 8) | (x[d] >>> 24);
      x[c] = (x[c] + x[d]) | 0; x[b] ^= x[c]; x[b] = (x[b] << 7) | (x[b] >>> 25);
    };

    for (let offset = 0; offset < data.length; offset += 64) {
      block.set(state);
      for (let round = 0; round < 10; round++) {
        qr(block, 0, 4, 8, 12); qr(block, 1, 5, 9, 13);
        qr(block, 2, 6, 10, 14); qr(block, 3, 7, 11, 15);
        qr(block, 0, 5, 10, 15); qr(block, 1, 6, 11, 12);
        qr(block, 2, 7, 8, 13); qr(block, 3, 4, 9, 14);
      }
      for (let i = 0; i < 16; i++) block[i] = (block[i] + state[i]) | 0;
      // Uint32Array shares the buffer, so blockBytes is the little endian
      // keystream on every platform browsers actually run on.
      const limit = Math.min(64, data.length - offset);
      for (let i = 0; i < limit; i++) out[offset + i] = data[offset + i] ^ blockBytes[i];
      state[12] = (state[12] + 1) | 0;
    }
    return out;
  }

  // ------------------------------------------------------------ secp256k1 --

  const P = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2fn;
  const N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141n;
  const Gx = 0x79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798n;
  const Gy = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8n;

  function mod(a, m = P) {
    const r = a % m;
    return r >= 0n ? r : r + m;
  }

  function powMod(base, exponent, m = P) {
    let result = 1n;
    let b = mod(base, m);
    let e = exponent;
    while (e > 0n) {
      if (e & 1n) result = (result * b) % m;
      b = (b * b) % m;
      e >>= 1n;
    }
    return result;
  }

  function invert(a, m = P) {
    if (a === 0n) throw new Error('cannot invert zero');
    let [old_r, r] = [mod(a, m), m];
    let [old_s, s] = [1n, 0n];
    while (r !== 0n) {
      const q = old_r / r;
      [old_r, r] = [r, old_r - q * r];
      [old_s, s] = [s, old_s - q * s];
    }
    return mod(old_s, m);
  }

  // Points in Jacobian coordinates: (x/z^2, y/z^3). Identity is z = 0.
  const IDENTITY = { x: 0n, y: 1n, z: 0n };
  const G = { x: Gx, y: Gy, z: 1n };

  function jacobianDouble(p) {
    if (p.z === 0n || p.y === 0n) return IDENTITY;
    const ySq = mod(p.y * p.y);
    const s = mod(4n * p.x * ySq);
    const m = mod(3n * p.x * p.x); // a = 0 for secp256k1
    const x = mod(m * m - 2n * s);
    return {
      x,
      y: mod(m * (s - x) - 8n * ySq * ySq),
      z: mod(2n * p.y * p.z),
    };
  }

  function jacobianAdd(p, q) {
    if (p.z === 0n) return q;
    if (q.z === 0n) return p;
    const pz2 = mod(p.z * p.z);
    const qz2 = mod(q.z * q.z);
    const u1 = mod(p.x * qz2);
    const u2 = mod(q.x * pz2);
    const s1 = mod(p.y * qz2 * q.z);
    const s2 = mod(q.y * pz2 * p.z);
    if (u1 === u2) return s1 === s2 ? jacobianDouble(p) : IDENTITY;
    const h = mod(u2 - u1);
    const r = mod(s2 - s1);
    const h2 = mod(h * h);
    const h3 = mod(h2 * h);
    const x = mod(r * r - h3 - 2n * u1 * h2);
    return {
      x,
      y: mod(r * (u1 * h2 - x) - s1 * h3),
      z: mod(h * p.z * q.z),
    };
  }

  function jacobianMultiply(point, scalar) {
    let k = mod(scalar, N);
    if (k === 0n) return IDENTITY;
    let result = IDENTITY;
    let addend = point;
    while (k > 0n) {
      if (k & 1n) result = jacobianAdd(result, addend);
      addend = jacobianDouble(addend);
      k >>= 1n;
    }
    return result;
  }

  function toAffine(p) {
    if (p.z === 0n) throw new Error('point at infinity');
    const zInv = invert(p.z);
    const zInv2 = mod(zInv * zInv);
    return { x: mod(p.x * zInv2), y: mod(p.y * zInv2 * zInv) };
  }

  function liftX(x) {
    if (x <= 0n || x >= P) throw new Error('x coordinate out of range');
    const ySq = mod(x * x * x + 7n);
    const y = powMod(ySq, (P + 1n) / 4n);
    if (mod(y * y) !== ySq) throw new Error('x is not on the curve');
    return { x, y: (y & 1n) === 0n ? y : P - y, z: 1n };
  }

  function taggedHash(tag, message) {
    const tagHash = sha256(utf8ToBytes(tag));
    return sha256(concatBytes(tagHash, tagHash, message));
  }

  /** x-only (BIP-340) public key for a 32 byte secret key. */
  function getPublicKey(secretKey) {
    const d = bytesToBigInt(secretKey);
    if (d <= 0n || d >= N) throw new Error('secret key out of range');
    return bigIntTo32Bytes(toAffine(jacobianMultiply(G, d)).x);
  }

  /** BIP-340 Schnorr signature over a 32 byte message. */
  function schnorrSign(message, secretKey, auxRandom) {
    if (message.length !== 32) throw new Error('message must be 32 bytes');
    const d0 = bytesToBigInt(secretKey);
    if (d0 <= 0n || d0 >= N) throw new Error('secret key out of range');
    const aux = auxRandom || randomBytes(32);

    const pointP = toAffine(jacobianMultiply(G, d0));
    const d = (pointP.y & 1n) === 0n ? d0 : N - d0;
    const px = bigIntTo32Bytes(pointP.x);

    const t = bigIntTo32Bytes(d ^ bytesToBigInt(taggedHash('BIP0340/aux', aux)));
    const rand = taggedHash('BIP0340/nonce', concatBytes(t, px, message));
    const k0 = mod(bytesToBigInt(rand), N);
    if (k0 === 0n) throw new Error('nonce was zero, retry');

    const pointR = toAffine(jacobianMultiply(G, k0));
    const k = (pointR.y & 1n) === 0n ? k0 : N - k0;
    const rx = bigIntTo32Bytes(pointR.x);

    const e = mod(bytesToBigInt(taggedHash('BIP0340/challenge', concatBytes(rx, px, message))), N);
    return concatBytes(rx, bigIntTo32Bytes(mod(k + e * d, N)));
  }

  /** Verify a BIP-340 signature. Returns false rather than throwing. */
  function schnorrVerify(signature, message, publicKey) {
    try {
      if (signature.length !== 64 || message.length !== 32 || publicKey.length !== 32) return false;
      const pointP = liftX(bytesToBigInt(publicKey));
      const r = bytesToBigInt(signature.slice(0, 32));
      const s = bytesToBigInt(signature.slice(32));
      if (r >= P || s >= N) return false;
      const e = mod(
        bytesToBigInt(taggedHash('BIP0340/challenge', concatBytes(signature.slice(0, 32), publicKey, message))),
        N,
      );
      const pointR = jacobianAdd(
        jacobianMultiply(G, s),
        jacobianMultiply(pointP, N - e),
      );
      if (pointR.z === 0n) return false;
      const affine = toAffine(pointR);
      return (affine.y & 1n) === 0n && affine.x === r;
    } catch (err) {
      return false;
    }
  }

  /** x coordinate of secretKey * peerPublicKey, as NIP-44 specifies. */
  function ecdhSharedX(secretKey, peerPublicKey) {
    const d = bytesToBigInt(secretKey);
    if (d <= 0n || d >= N) throw new Error('secret key out of range');
    const peer = liftX(bytesToBigInt(peerPublicKey));
    return bigIntTo32Bytes(toAffine(jacobianMultiply(peer, d)).x);
  }

  global.HRCrypto = {
    utf8ToBytes, bytesToUtf8, bytesToHex, hexToBytes, concatBytes, equalBytes, randomBytes,
    bytesToBase64, base64ToBytes, bytesToBigInt, bigIntTo32Bytes,
    sha256, hmacSha256, hkdfExtract, hkdfExpand, chacha20,
    getPublicKey, schnorrSign, schnorrVerify, ecdhSharedX,
  };
})(typeof window !== 'undefined' ? window : globalThis);
