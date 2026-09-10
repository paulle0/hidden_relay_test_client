# Web test client

A browser test client for the hidden relay. It takes your `nsec` and the
bridge's `nrv1…` address, publishes a kind 1 note through the hidden relay, and
fetches your own kind 1 notes back for display.

Plain HTML, CSS and JavaScript. No build step, no framework, no CDN, and no
network traffic other than the relay websocket itself.

## Using it

Open `index.html` in a browser. Double-clicking the file works; if your browser
is unhappy with `file://`, serve the folder instead:

```bash
./serve.sh          # then open http://127.0.0.1:8099/index.html
```

Then:

1. **Connect.** Paste your `nsec` and the bridge's `nrv1…` address. The address
   carries both the bridge pubkey and its rendez-vous relays, so nothing else
   is needed. Get it from `hidden-relay-bridge show` on the bridge, or from
   `keygen --relay …` when you created the identity.
2. **Publish.** Type some content and press the button. The note is signed in
   the browser, wrapped in an encrypted kind 27901 event and sent to the
   bridge, which replays it against the relay on the far side.
3. **Your notes.** Runs `REQ {"kinds":[1],"authors":[your pubkey]}` through the
   bridge. It refreshes automatically after a publish, and the signature of
   every note that comes back is verified in the browser.

The protocol log at the bottom shows every relay message going in and out, in
plaintext, which is usually the fastest way to see what a bridge is doing.

Your pubkey has to be in the bridge's `access.allowed_pubkeys`, otherwise the
bridge ignores you and requests simply time out.

### If the connection fails

- **Nothing happens on connect.** Check the rendez-vous relay URL. A page
  served over `https://` cannot open a `ws://` socket; use `wss://`, or open
  the page from `file://` or `http://`.
- **Requests time out.** Your pubkey is probably not whitelisted on the bridge.
- **"NIP-42 auth refused".** The relay wants an account it recognises.

## What is in here

```
index.html      the page
style.css       styling, light and dark
js/crypto.js    SHA-256, HMAC, HKDF, ChaCha20, secp256k1 / BIP-340
js/nostr.js     bech32 and NIP-19 (incl. nrv), NIP-44 v2, events, relay client
js/app.js       UI wiring
test/run-tests.js  runs the crypto against the official vectors under node
serve.sh        a one line static file server
```

`crypto.js` implements everything from scratch in plain JavaScript so the page
stays dependency free and works offline from a `file://` URL. It is **not
constant time** and makes no attempt to resist side channel attacks. This is a
test client: use a throwaway key, not one holding an identity you care about.

The "remember these inputs" checkbox stores the secret key in this browser's
`localStorage` in the clear. It is off by default; leave it off on a machine
you share.

## Tests

```bash
node test/run-tests.js
```

Runs the official NIP-44 v2 test vectors (the same file the Python suite uses)
against this JavaScript implementation, plus event id and signature checks
against a fixture generated with rust-nostr, tamper detection, sign/verify
round trips, and the NIP-19 codecs including the `nrv` TLV format. It needs
only node, no packages.

The page itself is covered end to end from the repository root: the browser
tests drive Chromium against a real bridge and two real relays, publishing and
reading notes back, both over `http://` and from a `file://` URL, and with a
rendez-vous relay that demands NIP-42 auth.
