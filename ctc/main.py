"""
End-to-end demo of the CTC protocol using the in-memory mock blockchain.

Demonstrates the three-party view:
  - Voter:    Setup → Commit → Open
  - Adversary: Leak (sees anonymity set, cannot identify registration)
  - Verifier:  Open succeeds for honest voter, fails for coerced fake
"""

from ctc.commitment import SHA256Commitment
from ctc.adapters.mock_blockchain import MockBlockchain
from ctc.ctc import CTC


def main() -> None:
    # ------------------------------------------------------------------ #
    # Setup                                                                #
    # ------------------------------------------------------------------ #
    chain  = MockBlockchain()
    scheme = SHA256Commitment()
    voter  = CTC(scheme, chain)
    pp = voter.setup()
    print(f"[Setup] public parameters (domain tag): {pp.decode()!r}\n")

    # ------------------------------------------------------------------ #
    # Cover traffic: background activity on the bulletin board             #
    # ------------------------------------------------------------------ #
    cover_voter = CTC(scheme, chain)
    cover_voter._pp = pp  # share public parameters
    for i in range(5):
        cover_voter.commit(f"noise-{i}".encode())
    print(f"[Cover] {chain.ledger_size()} background transactions posted.\n")

    # ------------------------------------------------------------------ #
    # Voter self-registers (covertly)                                      #
    # ------------------------------------------------------------------ #
    voting_credential = b"credential:alice:abc123"
    t = voter.commit(voting_credential)
    print(f"[Commit] Alice commits her voting credential at seq id t={t}")
    print(f"         Bulletin board now has {chain.ledger_size()} transactions.\n")

    # ------------------------------------------------------------------ #
    # Adversary's view via Leak                                            #
    # ------------------------------------------------------------------ #
    leaked = voter.leak()
    print(f"[Leak]   Adversary sees {len(leaked)} transactions.")
    print(f"         Each 'to' address is a pseudorandom truncation of SHA-256(pp||m||r),")
    print(f"         hiding Alice's credential among {len(leaked)} indistinguishable entries.")
    print(f"         Sample 'to': {leaked[t]['to']}\n")

    # ------------------------------------------------------------------ #
    # Voting phase: Alice opens her commitment to prove prior registration  #
    # ------------------------------------------------------------------ #
    valid = voter.open_local(t)
    print(f"[Open]   Alice opens commitment at t={t}: valid={valid}")

    # Coerced scenario: adversary tries to open with wrong credential
    record = voter._store[t]
    coerced_valid = voter.open(b"credential:alice:FAKE", record.r, t)
    print(f"[Open]   Adversary tries fake credential at t={t}: valid={coerced_valid}\n")

    # ------------------------------------------------------------------ #
    # Ordering guarantee                                                    #
    # ------------------------------------------------------------------ #
    t_late = voter.commit(b"credential:alice:COERCED")
    print(f"[Order]  Coerced registration at t={t_late} > honest registration at t={t}.")
    print(f"         Tallying picks the earliest -> honest registration wins.\n")

    print("Demo complete.")


if __name__ == "__main__":
    main()
