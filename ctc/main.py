"""
CTC demo: commit and open a voting credential over a USDT transfer on the Tron Nile testnet.

Required env vars (or .env file):
  TRON_TESTNET_NODE      — HTTP RPC URL, e.g. https://nile.trongrid.io
  TRON_PRIVATE_KEY       — 64-hex private key for a funded testnet account
  TRON_RECIPIENT         — Base58check address to receive the USDT transfer
  TRON_TRC20_CONTRACT    — USDT contract address on Nile testnet
  TRON_USDT_AMOUNT       — (optional) transfer amount in token units, default 1
  TRON_OPEN_DELAY        — (optional) seconds to wait before opening, default 30
"""

import os
import time
from pathlib import Path

from dotenv import load_dotenv
from tronpy import Tron
from tronpy.providers import HTTPProvider

from ctc.commitment import SHA3Commitment
from ctc.adapters.tron_blockchain import TronTRC20Blockchain
from ctc.ctc import CTC

load_dotenv(dotenv_path=Path(__file__).parent / ".env")


def main() -> None:
    node            = os.environ["TRON_TESTNET_NODE"]
    private_key_hex = os.environ["TRON_PRIVATE_KEY"]
    recipient       = os.environ["TRON_RECIPIENT"]
    contract        = os.environ["TRON_TRC20_CONTRACT"]
    amount          = int(os.environ.get("TRON_USDT_AMOUNT", "1"))
    open_delay      = int(os.environ.get("TRON_OPEN_DELAY", "30"))

    client = Tron(HTTPProvider(endpoint_uri=node), network="nile")
    chain  = TronTRC20Blockchain(
        client,
        signing_key_bytes=bytes.fromhex(private_key_hex),
        recipient=recipient,
        contract_address=contract,
        amount=amount,
    )
    voter = CTC(SHA3Commitment(), chain)
    voter.setup()

    # --- Commit ---------------------------------------------------------
    credential = b"credential:alice:abc123"
    print(f"[Commit] posting commitment for {credential!r} ...")
    t = voter.commit(credential)
    print(f"[Commit] confirmed — txid: {t}")

    # Opening receipt: what the voter would send to the tallier.
    m, r = voter.get_opening(t)
    print(f"[Open]   opening receipt:")
    print(f"           m = {m!r}")
    print(f"           r = {r.hex()}")
    print(f"           t = {t}")

    # --- Open -----------------------------------------------------------
    # Give the node a moment to index the transaction before looking it up.
    print(f"\n[Open]   waiting {open_delay}s for node indexing ...")
    time.sleep(open_delay)

    valid = voter.open(m, r, t)
    print(f"[Open]   commitment valid: {valid}")


if __name__ == "__main__":
    main()