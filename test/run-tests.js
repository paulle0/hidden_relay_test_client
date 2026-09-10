/*
 * Checks the browser client's crypto without a browser:
 *
 *     node webclient/test/run-tests.js
 *
 * Runs the official NIP-44 v2 vectors (the same file the Python test suite
 * uses) plus event id, signature and NIP-19 checks, so a change to crypto.js
 * or nostr.js cannot quietly break interoperability.
 */
'use strict';

const fs = require('fs');
const path = require('path');

globalThis.WebSocket = class {}; // nostr.js only needs the symbol to exist
require(path.join(__dirname, '..', 'js', 'crypto.js'));
require(path.join(__dirname, '..', 'js', 'nostr.js'));

const C = globalThis.HRCrypto;
const N = globalThis.HRNostr;

const vectorPath = path.join(__dirname, '..', '..', 'tests', 'vectors', 'nip44.vectors.json');
const V = JSON.parse(fs.readFileSync(vectorPath, 'utf8')).v2;

let passed = 0;
const failures = [];
function check(condition, label) {
  if (condition) passed++;
  else failures.push(label);
}
function checkThrows(fn, label) {
  try {
    fn();
    failures.push(label + ' (should have been rejected)');
  } catch (err) {
    passed++;
  }
}

// -- NIP-44 v2 -------------------------------------------------------------

for (const c of V.valid.get_conversation_key) {
  check(
    C.bytesToHex(N.getConversationKey(C.hexToBytes(c.sec1), c.pub2)) === c.conversation_key,
    `conversation key ${c.sec1.slice(0, 8)}`,
  );
}

for (const c of V.valid.encrypt_decrypt) {
  const pub2 = C.bytesToHex(C.getPublicKey(C.hexToBytes(c.sec2)));
  const key = N.getConversationKey(C.hexToBytes(c.sec1), pub2);
  check(C.bytesToHex(key) === c.conversation_key, `derived key ${c.sec1.slice(0, 8)}`);
  check(N.nip44Encrypt(c.plaintext, key, C.hexToBytes(c.nonce)) === c.payload, 'encrypt');
  check(N.nip44Decrypt(c.payload, key) === c.plaintext, 'decrypt');
}

for (const [input, expected] of V.valid.calc_padded_len) {
  check(N.calcPaddedLen(input) === expected, `padded length of ${input}`);
}

for (const c of V.valid.encrypt_decrypt_long_msg || []) {
  const plaintext = c.pattern.repeat(c.repeat);
  check(
    C.bytesToHex(C.sha256(C.utf8ToBytes(plaintext))) === c.plaintext_sha256,
    `long plaintext x${c.repeat}`,
  );
  const payload = N.nip44Encrypt(plaintext, C.hexToBytes(c.conversation_key), C.hexToBytes(c.nonce));
  check(
    C.bytesToHex(C.sha256(C.utf8ToBytes(payload))) === c.payload_sha256,
    `long payload x${c.repeat}`,
  );
}

for (const length of V.invalid.encrypt_msg_lengths) {
  checkThrows(
    () => N.nip44Encrypt('a'.repeat(length), new Uint8Array(32), new Uint8Array(32)),
    `plaintext length ${length}`,
  );
}
for (const c of V.invalid.decrypt) {
  checkThrows(() => N.nip44Decrypt(c.payload, C.hexToBytes(c.conversation_key)), `decrypt: ${c.note}`);
}
for (const c of V.invalid.get_conversation_key) {
  checkThrows(() => N.getConversationKey(C.hexToBytes(c.sec1), c.pub2), `conversation key: ${c.note}`);
}

// -- events ----------------------------------------------------------------

// Generated with the rust-nostr bindings, so this pins the browser code
// against an independent implementation. Non-ASCII on purpose.
const KNOWN = {
  id: '808320ded5c20394c9c0bb6a355897c548d76693718b344703282ba8cafcbeb4',
  pubkey: '7e7e9c42a91bfef19fa929e5fda1b72e0ebc1a4c1141673e2794234d86addf4e',
  created_at: 1673347337,
  kind: 1,
  tags: [
    ['e', '3da979448d9ba263864c4d6f14984c423a3838364ec255f03c7904b1ae77f206'],
    ['p', '3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d'],
  ],
  content:
    'Walled gardens became prisons, and nostr is the first step towards tearing down the prison walls. \u{1f30d} grüße',
  sig:
    'e9929337c22c544d5fac83a6b363db9e059364bdb9d7bb961fae43c4a0c2fc81' +
    'c88b00ad2281667ea3752407251d1a466b81fabc522c2ca4e20b0fe34c44cdbc',
};
const KNOWN_SECRET = '67dea2ed018072d675f5415ecfaed7d2597555e202d85b3d65ea4e58d2d92ffa';

check(N.eventId(KNOWN) === KNOWN.id, 'known event id');
check(N.verifyEvent(KNOWN) === true, 'known event signature');
check(C.bytesToHex(C.getPublicKey(C.hexToBytes(KNOWN_SECRET))) === KNOWN.pubkey, 'public key derivation');

const rebuilt = N.buildEvent(C.hexToBytes(KNOWN_SECRET), {
  kind: KNOWN.kind, content: KNOWN.content, tags: KNOWN.tags, created_at: KNOWN.created_at,
});
check(rebuilt.id === KNOWN.id, 'rebuilding the known event reproduces its id');
check(N.verifyEvent(rebuilt) === true, 'our own signature verifies');

for (const field of ['content', 'created_at', 'kind', 'sig']) {
  const mutated = { content: KNOWN.content + '!', created_at: 1, kind: 2, sig: '00'.repeat(64) }[field];
  check(N.verifyEvent({ ...KNOWN, [field]: mutated }) === false, `tampered ${field} is rejected`);
}

for (let i = 0; i < 20; i++) {
  const secretKey = C.randomBytes(32);
  const event = N.buildEvent(secretKey, { kind: 1, content: `round trip ${i} \u{1f30d}` });
  check(N.verifyEvent(event) === true, `sign/verify round trip ${i}`);
}

// -- NIP-19 ----------------------------------------------------------------

const NSEC = 'nsec1vl029mgpspedva04g90vltkh6fvh240zqtv9k0t9af8935ke9laqsnlfe5';
const NPUB = 'npub180cvv07tjdrrgpa0j7j7tmnyl2yr6yr7l8j4s3evf6u64th6gkwsyjh6w6';
const HEX_PUB = '3bf0c63fcb93463407af97a5e5ee64fa883d107ef9e558472c4eb9aaaefa459d';

check(C.bytesToHex(N.decodeNsec(NSEC)) === KNOWN_SECRET, 'nsec decodes');
check(N.encodeNpub(HEX_PUB) === NPUB, 'npub encodes');
check(N.decodeNpub(NPUB) === HEX_PUB, 'npub decodes');
check(C.bytesToHex(N.parseSecretKey(KNOWN_SECRET.toUpperCase())) === KNOWN_SECRET, 'hex secret key');

const relays = ['wss://relay.napttr.eu', 'ws://127.0.0.1:7802'];
const nrv = N.encodeNrv(HEX_PUB, relays);
const decoded = N.decodeNrv(nrv);
check(nrv.startsWith('nrv1'), 'nrv prefix');
check(decoded.pubkey === HEX_PUB, 'nrv pubkey round trip');
check(JSON.stringify(decoded.relays) === JSON.stringify(relays), 'nrv relays round trip');
check(JSON.stringify(N.decodeNrv(N.encodeNrv(HEX_PUB, [])).relays) === '[]', 'nrv without relays');
checkThrows(() => N.decodeNrv(NPUB), 'nrv decoder rejects an npub');
checkThrows(() => N.decodeNpub(NPUB.slice(0, -1) + (NPUB.endsWith('q') ? 'p' : 'q')), 'bad checksum');
checkThrows(() => N.parseSecretKey('not-a-key'), 'nonsense secret key');

// -- report ----------------------------------------------------------------

if (failures.length) {
  console.error(`\n${failures.length} FAILED:`);
  for (const failure of failures) console.error('  - ' + failure);
  console.error(`\n${passed} passed, ${failures.length} failed`);
  process.exit(1);
}
console.log(`${passed} checks passed`);
