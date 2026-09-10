/*
 * Nostr protocol layer for the hidden relay test client: bech32 / NIP-19
 * (including the nrv address), event ids and signatures, NIP-44 v2, a small
 * relay websocket wrapper, and the client half of the hidden relay NIP.
 *
 * Exposed as window.HRNostr. Depends on crypto.js being loaded first.
 */
(function (global) {
  'use strict';

  const C = global.HRCrypto;

  const KIND_RENDEZVOUS_LIST = 10112;
  const KIND_RELAY_INFORMATION = 10113;
  const KIND_COMMUNICATION = 27901;
  const KIND_CLIENT_AUTH = 22242;
  const ENCRYPTION = 'nip44_v2';

  // --------------------------------------------------------------- bech32 --

  const CHARSET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l';

  function polymod(values) {
    const generator = [0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3];
    let chk = 1;
    for (const value of values) {
      const top = chk >> 25;
      chk = ((chk & 0x1ffffff) << 5) ^ value;
      for (let i = 0; i < 5; i++) if ((top >> i) & 1) chk ^= generator[i];
    }
    return chk;
  }

  function hrpExpand(hrp) {
    const out = [];
    for (const ch of hrp) out.push(ch.charCodeAt(0) >> 5);
    out.push(0);
    for (const ch of hrp) out.push(ch.charCodeAt(0) & 31);
    return out;
  }

  function convertBits(data, from, to, pad) {
    let acc = 0;
    let bits = 0;
    const out = [];
    const maxv = (1 << to) - 1;
    for (const value of data) {
      if (value < 0 || value >> from !== 0) throw new Error('invalid value in base conversion');
      acc = (acc << from) | value;
      bits += from;
      while (bits >= to) {
        bits -= to;
        out.push((acc >> bits) & maxv);
      }
    }
    if (pad) {
      if (bits > 0) out.push((acc << (to - bits)) & maxv);
    } else if (bits >= from || ((acc << (to - bits)) & maxv)) {
      throw new Error('invalid padding in base conversion');
    }
    return out;
  }

  function bech32Decode(text) {
    if (text !== text.toLowerCase() && text !== text.toUpperCase()) {
      throw new Error('mixed case bech32 string');
    }
    const lower = text.toLowerCase().trim();
    const pos = lower.lastIndexOf('1');
    if (pos < 1 || pos + 7 > lower.length) throw new Error('missing or misplaced separator');
    const hrp = lower.slice(0, pos);
    const data = [];
    for (const ch of lower.slice(pos + 1)) {
      const index = CHARSET.indexOf(ch);
      if (index === -1) throw new Error(`invalid bech32 character '${ch}'`);
      data.push(index);
    }
    if (polymod(hrpExpand(hrp).concat(data)) !== 1) throw new Error('bad checksum');
    return { hrp, bytes: new Uint8Array(convertBits(data.slice(0, -6), 5, 8, false)) };
  }

  function bech32Encode(hrp, bytes) {
    const data = convertBits(Array.from(bytes), 8, 5, true);
    const values = hrpExpand(hrp).concat(data);
    const mod = polymod(values.concat([0, 0, 0, 0, 0, 0])) ^ 1;
    const checksum = [];
    for (let i = 0; i < 6; i++) checksum.push((mod >> (5 * (5 - i))) & 31);
    return hrp + '1' + data.concat(checksum).map((d) => CHARSET[d]).join('');
  }

  // --------------------------------------------------------------- NIP-19 --

  function decodeNsec(text) {
    const { hrp, bytes } = bech32Decode(text);
    if (hrp !== 'nsec') throw new Error(`expected an nsec, got '${hrp}'`);
    if (bytes.length !== 32) throw new Error('nsec payload must be 32 bytes');
    return bytes;
  }

  function encodeNpub(pubkeyHex) {
    return bech32Encode('npub', C.hexToBytes(pubkeyHex));
  }

  function decodeNpub(text) {
    const { hrp, bytes } = bech32Decode(text);
    if (hrp !== 'npub') throw new Error(`expected an npub, got '${hrp}'`);
    if (bytes.length !== 32) throw new Error('npub payload must be 32 bytes');
    return C.bytesToHex(bytes);
  }

  /**
   * Decode an nrv address into { pubkey, relays }.
   * TLV 0 is the hidden relay pubkey, TLV 1 is a rendez-vous relay (repeatable).
   */
  function decodeNrv(text) {
    const { hrp, bytes } = bech32Decode(text);
    if (hrp !== 'nrv') throw new Error(`expected an nrv address, got '${hrp}'`);
    let pubkey = null;
    const relays = [];
    let index = 0;
    while (index < bytes.length) {
      if (index + 2 > bytes.length) throw new Error('truncated TLV header');
      const type = bytes[index];
      const length = bytes[index + 1];
      index += 2;
      if (index + length > bytes.length) throw new Error('truncated TLV value');
      const value = bytes.slice(index, index + length);
      index += length;
      if (type === 0) {
        if (value.length !== 32) throw new Error('nrv pubkey must be 32 bytes');
        pubkey = C.bytesToHex(value);
      } else if (type === 1) {
        relays.push(new TextDecoder().decode(value));
      }
    }
    if (!pubkey) throw new Error('nrv address carries no pubkey');
    return { pubkey, relays };
  }

  function encodeNrv(pubkeyHex, relays) {
    const parts = [Uint8Array.of(0, 32), C.hexToBytes(pubkeyHex)];
    for (const relay of relays || []) {
      const encoded = new TextEncoder().encode(relay);
      parts.push(Uint8Array.of(1, encoded.length), encoded);
    }
    return bech32Encode('nrv', C.concatBytes(...parts));
  }

  /** Accept an nsec or 64 character hex and return the raw secret key. */
  function parseSecretKey(text) {
    const value = (text || '').trim();
    if (value.startsWith('nsec1')) return decodeNsec(value);
    if (/^[0-9a-fA-F]{64}$/.test(value)) return C.hexToBytes(value.toLowerCase());
    throw new Error('expected an nsec1... key or 64 hex characters');
  }

  // --------------------------------------------------------------- NIP-44 --

  function calcPaddedLen(unpaddedLen) {
    if (unpaddedLen < 1) throw new Error('plaintext must not be empty');
    if (unpaddedLen <= 32) return 32;
    const nextPower = 1 << (32 - Math.clz32(unpaddedLen - 1));
    const chunk = nextPower <= 256 ? 32 : nextPower / 8;
    return chunk * (Math.floor((unpaddedLen - 1) / chunk) + 1);
  }

  function getConversationKey(secretKey, peerPublicKeyHex) {
    const shared = C.ecdhSharedX(secretKey, C.hexToBytes(peerPublicKeyHex));
    return C.hkdfExtract(C.utf8ToBytes('nip44-v2'), shared);
  }

  function getMessageKeys(conversationKey, nonce) {
    const keys = C.hkdfExpand(conversationKey, nonce, 76);
    return {
      chachaKey: keys.slice(0, 32),
      chachaNonce: keys.slice(32, 44),
      hmacKey: keys.slice(44, 76),
    };
  }

  function nip44Encrypt(plaintext, conversationKey, nonce) {
    const unpadded = C.utf8ToBytes(plaintext);
    if (unpadded.length < 1 || unpadded.length > 65535) {
      throw new Error(`plaintext of ${unpadded.length} bytes is out of range`);
    }
    const n = nonce || C.randomBytes(32);
    const { chachaKey, chachaNonce, hmacKey } = getMessageKeys(conversationKey, n);
    const padded = C.concatBytes(
      Uint8Array.of(unpadded.length >> 8, unpadded.length & 0xff),
      unpadded,
      new Uint8Array(calcPaddedLen(unpadded.length) - unpadded.length),
    );
    const ciphertext = C.chacha20(chachaKey, chachaNonce, padded);
    const mac = C.hmacSha256(hmacKey, C.concatBytes(n, ciphertext));
    return C.bytesToBase64(C.concatBytes(Uint8Array.of(2), n, ciphertext, mac));
  }

  function nip44Decrypt(payload, conversationKey) {
    if (!payload) throw new Error('empty payload');
    if (payload[0] === '#') throw new Error('unknown encryption version');
    if (payload.length < 132 || payload.length > 87472) {
      throw new Error(`invalid payload length: ${payload.length}`);
    }
    const raw = C.base64ToBytes(payload);
    if (raw.length < 99 || raw.length > 65603) throw new Error(`invalid payload size: ${raw.length}`);
    if (raw[0] !== 2) throw new Error(`unknown encryption version ${raw[0]}`);
    const nonce = raw.slice(1, 33);
    const ciphertext = raw.slice(33, raw.length - 32);
    const mac = raw.slice(raw.length - 32);
    const { chachaKey, chachaNonce, hmacKey } = getMessageKeys(conversationKey, nonce);
    if (!C.equalBytes(C.hmacSha256(hmacKey, C.concatBytes(nonce, ciphertext)), mac)) {
      throw new Error('invalid MAC');
    }
    const padded = C.chacha20(chachaKey, chachaNonce, ciphertext);
    const length = (padded[0] << 8) | padded[1];
    const unpadded = padded.slice(2, 2 + length);
    if (length < 1 || unpadded.length !== length || padded.length !== 2 + calcPaddedLen(length)) {
      throw new Error('invalid padding');
    }
    return C.bytesToUtf8(unpadded);
  }

  // ---------------------------------------------------------------- events --

  /**
   * NIP-01 serialization. JSON.stringify already produces the compact form and
   * the escaping NIP-01 requires, and the id is the sha256 of its UTF-8 bytes.
   */
  function eventId(event) {
    const serialized = JSON.stringify([
      0, event.pubkey, event.created_at, event.kind, event.tags, event.content,
    ]);
    return C.bytesToHex(C.sha256(C.utf8ToBytes(serialized)));
  }

  function buildEvent(secretKey, { kind, content = '', tags = [], created_at }) {
    const event = {
      pubkey: C.bytesToHex(C.getPublicKey(secretKey)),
      created_at: created_at || Math.floor(Date.now() / 1000),
      kind,
      tags,
      content,
    };
    event.id = eventId(event);
    event.sig = C.bytesToHex(C.schnorrSign(C.hexToBytes(event.id), secretKey));
    return event;
  }

  function verifyEvent(event) {
    try {
      if (!event || typeof event.id !== 'string' || event.id.length !== 64) return false;
      if (typeof event.sig !== 'string' || event.sig.length !== 128) return false;
      if (eventId(event) !== event.id) return false;
      return C.schnorrVerify(C.hexToBytes(event.sig), C.hexToBytes(event.id), C.hexToBytes(event.pubkey));
    } catch (err) {
      return false;
    }
  }

  function firstTag(event, name) {
    for (const tag of event.tags || []) if (tag[0] === name && tag.length >= 2) return tag[1];
    return null;
  }

  function tagValues(event, name) {
    return (event.tags || []).filter((t) => t[0] === name && t.length >= 2).map((t) => t[1]);
  }

  // ------------------------------------------------------------ relay link --

  /**
   * One websocket to one relay. Answers NIP-42 AUTH with the given key and
   * hands every other message to onMessage.
   */
  class RelayLink {
    constructor(url, secretKey, { onMessage, onStatus, onAuthenticated } = {}) {
      this.url = url;
      this.secretKey = secretKey;
      this.onMessage = onMessage || (() => {});
      this.onStatus = onStatus || (() => {});
      this.onAuthenticated = onAuthenticated || (() => {});
      this.socket = null;
      this.authenticated = false;
      this.authEventId = null;
    }

    connect(timeoutMs = 15000) {
      return new Promise((resolve, reject) => {
        let socket;
        try {
          socket = new WebSocket(this.url);
        } catch (err) {
          reject(new Error(`could not open ${this.url}: ${err.message}`));
          return;
        }
        this.socket = socket;
        const timer = setTimeout(() => {
          socket.close();
          reject(new Error(`timed out connecting to ${this.url}`));
        }, timeoutMs);

        socket.onopen = () => {
          clearTimeout(timer);
          this.onStatus('connected', this.url);
          resolve();
        };
        socket.onerror = () => {
          clearTimeout(timer);
          reject(new Error(`could not connect to ${this.url}`));
        };
        socket.onclose = () => {
          this.onStatus('closed', this.url);
        };
        socket.onmessage = (frame) => {
          let message;
          try {
            message = JSON.parse(frame.data);
          } catch (err) {
            return;
          }
          if (!Array.isArray(message) || message.length === 0) return;
          if (message[0] === 'AUTH' && typeof message[1] === 'string') {
            this.answerAuth(message[1]);
            return;
          }
          if (message[0] === 'OK' && message[1] === this.authEventId) {
            this.authEventId = null;
            if (message[2] === true) {
              this.authenticated = true;
              this.onStatus('auth', 'authenticated to ' + this.url);
              this.onAuthenticated();
            } else {
              this.onStatus('warn', `NIP-42 auth refused: ${message[3] || ''}`);
            }
            return;
          }
          this.onMessage(message);
        };
      });
    }

    answerAuth(challenge) {
      const event = buildEvent(this.secretKey, {
        kind: KIND_CLIENT_AUTH,
        tags: [['relay', this.url], ['challenge', challenge]],
      });
      this.onStatus('auth', 'answering NIP-42 challenge');
      this.authEventId = event.id;
      this.send(['AUTH', event]);
    }

    send(message) {
      if (!this.socket || this.socket.readyState !== WebSocket.OPEN) {
        throw new Error('not connected');
      }
      this.socket.send(JSON.stringify(message));
    }

    close() {
      if (this.socket) {
        this.socket.onclose = null;
        this.socket.close();
        this.socket = null;
      }
    }

    get isOpen() {
      return !!this.socket && this.socket.readyState === WebSocket.OPEN;
    }
  }

  // --------------------------------------------------- hidden relay client --

  /**
   * Speaks the client half of the hidden relay NIP: wrap NIP-01 messages in an
   * encrypted kind 27901 event, publish it to the rendez-vous relay, and unwrap
   * whatever the bridge sends back.
   */
  class HiddenRelayClient {
    constructor({ secretKey, bridgePubkey, relayUrl, onRelayMessage, onStatus }) {
      this.secretKey = secretKey;
      this.pubkey = C.bytesToHex(C.getPublicKey(secretKey));
      this.bridgePubkey = bridgePubkey;
      this.relayUrl = relayUrl;
      this.onRelayMessage = onRelayMessage || (() => {});
      this.onStatus = onStatus || (() => {});
      this.conversationKey = getConversationKey(secretKey, bridgePubkey);
      this.seenEventIds = new Set();
      this.pendingRequests = new Map(); // subscription id -> collector
      this.pendingPublishes = new Map(); // event id -> resolver
      this.subscriptionCounter = 0;
      this.link = new RelayLink(relayUrl, secretKey, {
        onMessage: (message) => this.handleRelayMessage(message),
        onStatus: this.onStatus,
        onAuthenticated: () => this.subscribeInbox(),
      });
    }

    static fromNrv({ nsec, nrv, relayUrl, onRelayMessage, onStatus }) {
      const secretKey = parseSecretKey(nsec);
      const { pubkey, relays } = decodeNrv(nrv);
      const url = relayUrl || relays[0];
      if (!url) throw new Error('the nrv address carries no relay, enter one manually');
      return new HiddenRelayClient({
        secretKey, bridgePubkey: pubkey, relayUrl: url, onRelayMessage, onStatus,
      });
    }

    async connect(timeoutMs) {
      await this.link.connect(timeoutMs);
      this.subscribeInbox();
    }

    /**
     * Subscribe to kind 27901 events the bridge addressed to us. Re-issued
     * after a NIP-42 handshake, because a relay that demands AUTH will have
     * refused the subscription we sent as soon as the socket opened.
     */
    subscribeInbox() {
      this.link.send(['REQ', 'inbox', {
        kinds: [KIND_COMMUNICATION],
        authors: [this.bridgePubkey],
        '#p': [this.pubkey],
        since: Math.floor(Date.now() / 1000) - 60,
      }]);
    }

    close() {
      this.link.close();
    }

    /** Wrap NIP-01 messages in one kind 27901 event and publish it. */
    send(messages) {
      const plaintext = JSON.stringify(messages);
      const event = buildEvent(this.secretKey, {
        kind: KIND_COMMUNICATION,
        content: nip44Encrypt(plaintext, this.conversationKey),
        tags: [['p', this.bridgePubkey], ['encryption', ENCRYPTION]],
      });
      this.link.send(['EVENT', event]);
      return event;
    }

    handleRelayMessage(message) {
      if (message[0] !== 'EVENT' || !message[2]) {
        if (message[0] === 'OK' && message[2] === false) {
          this.onStatus('warn', `rendez-vous relay rejected our event: ${message[3] || ''}`);
        } else if (message[0] === 'CLOSED') {
          this.onStatus('warn', `rendez-vous relay closed our inbox: ${message[2] || ''}`);
        } else if (message[0] === 'NOTICE') {
          this.onStatus('warn', `rendez-vous notice: ${message[1] || ''}`);
        }
        return;
      }
      const event = message[2];
      if (event.kind !== KIND_COMMUNICATION || event.pubkey !== this.bridgePubkey) return;
      if (!tagValues(event, 'p').includes(this.pubkey)) return;
      if (this.seenEventIds.has(event.id)) return;
      this.seenEventIds.add(event.id);
      if (!verifyEvent(event)) {
        this.onStatus('warn', `dropping bridge event ${event.id.slice(0, 12)}: bad signature`);
        return;
      }
      let payload;
      try {
        payload = JSON.parse(nip44Decrypt(event.content, this.conversationKey));
      } catch (err) {
        this.onStatus('warn', `could not read bridge event: ${err.message}`);
        return;
      }
      if (!Array.isArray(payload)) return;
      for (const relayMessage of payload) {
        if (!Array.isArray(relayMessage) || !relayMessage.length) continue;
        this.onRelayMessage(relayMessage);
        this.dispatch(relayMessage);
      }
    }

    /** Route one unwrapped relay message to whoever is waiting for it. */
    dispatch(message) {
      const [verb, first] = message;
      if (verb === 'EVENT') {
        const collector = this.pendingRequests.get(first);
        if (collector && message[2]) collector.events.push(message[2]);
      } else if (verb === 'EOSE') {
        const collector = this.pendingRequests.get(first);
        if (collector) collector.finish(collector.events);
      } else if (verb === 'CLOSED') {
        const collector = this.pendingRequests.get(first);
        if (collector) collector.fail(new Error(message[2] || 'subscription closed'));
      } else if (verb === 'OK') {
        const resolver = this.pendingPublishes.get(first);
        if (resolver) resolver(message);
      }
    }

    /** Run a REQ through the bridge and resolve with the events up to EOSE. */
    request(filters, { subId, timeoutMs = 20000 } = {}) {
      const id = subId || `q${++this.subscriptionCounter}`;
      return new Promise((resolve, reject) => {
        const collector = {
          events: [],
          finish: (events) => {
            cleanup();
            resolve(events);
          },
          fail: (error) => {
            cleanup();
            reject(error);
          },
        };
        const timer = setTimeout(
          () => collector.fail(new Error(`no answer for '${id}' after ${timeoutMs / 1000}s`)),
          timeoutMs,
        );
        const cleanup = () => {
          clearTimeout(timer);
          this.pendingRequests.delete(id);
          try {
            this.send([['CLOSE', id]]);
          } catch (err) {
            /* the socket is already gone; nothing to close */
          }
        };
        this.pendingRequests.set(id, collector);
        try {
          this.send([['REQ', id, ...filters]]);
        } catch (err) {
          cleanup();
          reject(err);
        }
      });
    }

    /** Publish an event through the bridge and resolve with the relay's OK. */
    publish(event, { timeoutMs = 20000 } = {}) {
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          this.pendingPublishes.delete(event.id);
          reject(new Error(`no OK for ${event.id.slice(0, 12)} after ${timeoutMs / 1000}s`));
        }, timeoutMs);
        this.pendingPublishes.set(event.id, (message) => {
          clearTimeout(timer);
          this.pendingPublishes.delete(event.id);
          if (message[2] === true) resolve(message);
          else reject(new Error(message[3] || 'the relay rejected the event'));
        });
        try {
          this.send([['EVENT', event]]);
        } catch (err) {
          clearTimeout(timer);
          this.pendingPublishes.delete(event.id);
          reject(err);
        }
      });
    }
  }

  global.HRNostr = {
    KIND_RENDEZVOUS_LIST, KIND_RELAY_INFORMATION, KIND_COMMUNICATION, ENCRYPTION,
    bech32Decode, bech32Encode,
    decodeNsec, encodeNpub, decodeNpub, decodeNrv, encodeNrv, parseSecretKey,
    calcPaddedLen, getConversationKey, nip44Encrypt, nip44Decrypt,
    eventId, buildEvent, verifyEvent, firstTag, tagValues,
    RelayLink, HiddenRelayClient,
  };
})(typeof window !== 'undefined' ? window : globalThis);
