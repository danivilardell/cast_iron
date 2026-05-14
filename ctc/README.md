# Covert Timestamped Commitments (CTC)

A Python implementation of the CTC cryptographic primitive from the Cast Iron coercion-resistant e-voting protocol.

## What this does

A CTC lets a voter secretly register their voting credential on a public blockchain _before_ the election, in a way that:

- **Cannot be detected** — the registration transaction is indistinguishable from ordinary blockchain traffic.
- **Cannot be backdated** — opening the commitment proves both the content and the exact time it was posted, via the blockchain's immutable ordering.

This breaks the coercion attack: a coercer cannot tell whether a voter has already registered (covertness), and if they force the voter to register under duress, the honest prior registration takes precedence (timestamp binding).

## Construction

The protocol has three operations:

- **Setup** — generates public parameters `pp` (a domain-separation tag).
- **Commit(m)** — samples randomness `r`, computes `c = SHA3-256(pp, m, r)`, embeds `c` in a blockchain transaction, and returns a sequence ID `t`. Locally stores `(m, r)`.
- **Open(m, r, t)** — recomputes `c` from `(m, r)`, retrieves the transaction at `t`, and verifies the embedding. No private key needed for verification.

### Embedding: ECDSA nonce

Commitment `c` is embedded as the ECDSA signature nonce `k = SHA3-256(c) mod n` in a minimal transfer. On-chain, the signature's `r` value equals `(k·G).x`, invisibly encoding `c`. An observer sees an ordinary transfer with no distinguishing features.

**Anonymity set:** every transaction on-chain in a configurable block window — much larger than any transfer-specific set.

**Verification** is fully public: given `c`, compute `k`, then check `(k·G).x == signature_r`. No private key required.

**Key compromise:** revealing `c` at opening allows recovery of the signing private key from the public on-chain signature. This is mitigated by (a) encrypting `(m, r)` to the tallier only — the tallier is already trusted with vote content — and (b) using a minimal-funds signing address. The natural pattern is a _rotating address_: the commitment transaction sweeps all funds to a fresh key, leaving the old address empty.

### Why not fund-transfer embedding?

The paper's original construction transfers a small amount to an address _derived from_ `c`, with the anonymity set defined as transfers to first-time receiver addresses. We explored this on Tron (high USDT transfer volume) and rejected it for two reasons:

1. **Account activation.** Tron requires a destination account to exist on-chain before it can receive TRC-20 tokens. Addresses derived from `c` are fresh by construction, so every commitment transaction fails with `CONTRACT_VALIDATE_ERROR`. Working around this requires a preceding TRX activation transaction, which creates a two-transaction fingerprint and shrinks the anonymity set.

2. **Anonymity set size.** Even without the activation problem, the set of USDT transfers to first-time receivers is a small, distinctive subset of chain activity. Any filter over that set immediately halves the candidates for a covert commitment.

ECDSA nonce embedding has neither problem: it works on any chain with compatible ECDSA transfers without chain-level constraints, and its anonymity set is the entire transaction graph.

### Why not use a hardware wallet?

Hardware wallets (Ledger, Trezor, etc.) deliberately never expose or accept the ECDSA nonce `k` — RFC 6979 deterministic-k derivation is a firmware-level security invariant, because user-controlled `k` allows private key recovery. There is no API on any mainstream hardware wallet to inject a custom nonce.

This requires the CTC signing key to be a software key. That is not a regression: in Cast Iron, the hardware wallet's role is to sign the _binding between the issuing credential and the voting credential_, a separate operation on a separate key. The CTC commitment transaction uses an independent burner key; the hardware wallet is uninvolved in that step.

## Layout

```
ctc/
├── commitment.py          # CommitmentScheme ABC + SHA3Commitment
├── blockchain.py          # Blockchain ABC (embed, post, seq, lookup, filter, verify_embedding)
├── ctc.py                 # Π_CTC protocol (setup, commit, leak, open)
└── adapters/
    ├── mock_blockchain.py  # In-memory mock for tests (fund-transfer style)
    ├── eth_blockchain.py   # Ethereum adapter: ECDSA-nonce embedding via web3.py
    └── tron_blockchain.py  # Tron adapter: ECDSA-nonce embedding via TronPy
```

## Usage

```python
from ctc import CTC, SHA3Commitment, MockBlockchain

chain = MockBlockchain()
voter = CTC(SHA3Commitment(), chain)
voter.setup()

t = voter.commit(b"credential:alice:abc123")   # post commitment
assert voter.open_local(t)                      # verify it
```

For a live demo: `python main.py`

## Tron testnet

Set credentials in a `.env` file (never commit this):

```
ETH_TESTNET_NODE=https://sepolia.infura.io/v3/<key>
ETH_PRIVATE_KEY=<64-hex private key, minimal funds only>
ETH_RECIPIENT=<any address, can be same as sender>
```

Then:

```python
from tronpy import Tron
from ctc import CTC, SHA3Commitment
from ctc.adapters.tron_blockchain import TronNonceBlockchain

client = Tron(network="nile")
chain = TronNonceBlockchain(client, signing_key_bytes=bytes.fromhex("<key>"), recipient="T...")
voter = CTC(SHA3Commitment(), chain)
voter.setup()
t = voter.commit(b"my credential")
```

Run integration tests (requires env vars above):

```
pytest tests/test_tron_ctc.py
```

## Dependencies

- `web3>=7` — Ethereum RPC and transaction broadcasting
- `tronpy>=0.5` — Tron RPC, transaction building, and broadcasting
- `ecdsa>=0.19` — ECDSA signing with user-supplied nonce `k`
