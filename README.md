This repo contains code that allows people to independently verify the correctness of a Proof of Solvency using the ZeKnow Solv Protocol by Proven. All of this functionality is also available at our website: www.solvenscan.io

Summary:
The ZeKnow Solv Protocol constructs a ZK-SNARK where the prover shows that its Total Assets >= Total Liabilities without revealing any additional information. The way this works at a high-level is outlined here:

- The prover creates a Proof of Total Assets by using some publicly revealed data:
  - e.g. snapshots of each blockchain
- The prover creates a Proof of Total Liabilities by creating a Merkle Tree out of each individual liability.
- The prover feeds these two proofs into a Proof of Solvency, which does the following:
  - Checks the correctness of both the Proof of Assets and the Proof of Liabilities
  - Checks that Assets >= Liabilities
  - Reveals a series of public outputs that necessarily were used in the Proof of Assets and the Proof of Liabilities.

Only this final Proof of Solvency is revealed publicly. That is:

- a mathematical ZK-SNARK proof object
- a dictionary of public outputs

To each liability holder, the prover gives a receipt that proves this liability was uniquely included in the Proof-of-Liabilities.

---

In order to check the validity of the Solvency Claim. One must take the following steps:

- Verify the public outputs' veracity (i.e. were the inputs to the ZK-SNARK appropriate?)
- Verify the ZK-SNARK proof using the public outputs
- Verify your liability was included in the total liabilities calculation

---

VERIFY THE PUBLIC OUTPUTS VERACITY:

- Randomly check some addresses in the snapshot files. Make sure that their corresponding balances do match
  what they ought to be.
  (Code to help automate this is coming soon, for now it is manual)

---

VERIFY THE ZK SNARK PROOF USING THE PUBLIC OUTPUTS

- Use the generate_snapshot_hash.py file to calculate the expected snapshot hashes that would be used in the Proof of Assets
- Ensure that the verifying key hashes in the public outputs file match what Proven has committed they ought to be (coming soon)
- Use verify_public_outputs.py to check that these human readable public outputs hash to the single public-input that the top level ZK SNARK used (target_pubhash).
- Use verify_proof.py with the top-SNARK verifying key, SNARK Proof Object, and Public Input to verify the ZK SNARK Proof itself is valid.

---

VERIFY UNIQUE INCLUSION IN THE PROOF OF LIABILITIES:

- Use verify_receipt.py to check that your receipt is valid. Ensure that the merkle root on your receipt matches the merkle root in the proof.

---

We have provided convenient sample files that come from the same test-proof:

- sample_proof.json
- sample_receipt.json
- sample_public_outputs.json
- sample_X_snapshot.csv (Note that these snapshots are TEST snapshots and do not accurately reflect the state of the blockchain!)

With these files, you should be able to do the following verifications

- VERIFY THE ZK SNARK PROOF USING THE PUBLIC OUTPUTS
- VERIFY UNIQUE INCLUSION IN THE PROOF OF LIABILITIES
