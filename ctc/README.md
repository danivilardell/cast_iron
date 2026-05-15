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

**Verification** is fully public: given `c`, compute `k`, then check `(k·G).x == signature_r`. No private key required.

**Key compromise:** revealing `c` at opening allows recovery of the signing private key from the public on-chain signature. Mitigated by (a) encrypting `(m, r)` to the tallier only, and (b) using a rotating signing address — set `amount` to the full account balance so the commitment transaction sweeps the account clean, leaving the old key worthless.

## Layout

```
ctc/
├── commitment.py          # CommitmentScheme ABC + SHA3Commitment
├── blockchain.py          # Blockchain ABC (embed, post, seq, lookup, verify_embedding)
├── ctc.py                 # Π_CTC protocol (setup, commit, open)
└── adapters/
    ├── mock_blockchain.py  # In-memory mock for tests
    ├── eth_blockchain.py   # Ethereum: ECDSA-nonce embedding via EIP-1559 transfer
    └── tron_blockchain.py  # Tron: TRX transfer (TronNonceBlockchain)
                            #       TRC-20 transfer (TronTRC20Blockchain)
```

## Demo

`main.py` runs a commit/open cycle over a USDT transfer on the Tron Nile testnet.

Set credentials in a `.env` file (never commit this):

```
TRON_TESTNET_NODE=https://nile.trongrid.io
TRON_PRIVATE_KEY=<64-hex private key, minimal funds only>
TRON_RECIPIENT=<base58check address to receive the transfer>
TRON_TRC20_CONTRACT=<USDT contract address on Nile>
TRON_USDT_AMOUNT=1
```

Then:

```
python main.py
```

## Dependencies

- `web3>=7` — Ethereum RPC and transaction broadcasting
- `tronpy>=0.5` — Tron RPC, transaction building, and broadcasting
- `ecdsa>=0.19` — ECDSA signing with user-supplied nonce `k`