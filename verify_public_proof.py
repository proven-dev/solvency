"""
ZK-Proof of Solvency consists of two parts. Assets and Liabilities. Ultimately it proves that Assets >= Liabilities for each token.

Under the hood, many proofs are being composed with one another into one top-level proof. This top level proof takes in a Proof of Assets and a Proof of Liabilities.
It ensures that for each token, Assets >= Liabilities, and that each of these proofs are valid. It cannot verify the full authenticity of the proofs themselves, so what it
cannot verify, it passes through the public outputs of the Assets Proof and the public outputs of the Liabilities Proof.

e.g. in the case of the liabilities proof, the top solvency zk proof passes through the Merkle Root, just believing the liabilities proof's claim on what the total liabilities owed are.

Therefore it is up to the verifier to verify the authenticity of the public outputs of the Assets Proof and the Liabilities Proof.

Using the Liabilities Proof Outputs and the Assets Proof Outputs, the verifier can construct a final hash value, which is used as the "public input" to the top level SNARK proof object.
If we trust the public inputs, then we can use math to verify that the top level proof is valid. The mathematical properties that check whether a ZK Proof of Solvency is valid for a specific
final hash value is checked in a smart contract on the Ethereum blockchain for convenience.

Here is a link to that smart contract: https://etherscan.io/address/0xa3965810538b8b688e3ca06c2f188b74b397854a
"""
import json
from utils.common import int_to_regs
from utils.poseidon.poseidon_hash import poseidon_hash

VERBOSE = True


def print_verbose(x: str):
    if VERBOSE:
        print(x)


def hash_pub_outputs(pub_outputs, print_fn=None) -> int:
    if print_fn == None:
        print_fn = print_verbose
    print_fn(f"Inside hash_pub_outputs. pub_outputs = {pub_outputs}")
    liab_hash: int = hash_liab_pub_outputs(pub_outputs['liabilities'])
    print_fn(f"liab_hash: {liab_hash}")
    assets_hash: int = hash_asset_pub_outputs(pub_outputs['assets'], print_fn)
    print_fn(f"assets_hash: {assets_hash}")
    final_hash: int = poseidon_hash([assets_hash, liab_hash], 2)
    print_fn(f"final_hash: {final_hash}")
    return final_hash


def hash_liab_pub_outputs(liabilities_pub_outputs: dict) -> int:
    # component poseidon = Poseidon(3);
    # poseidon.inputs[0] <== root;
    # poseidon.inputs[1] <== hashed_vkey_base;
    # poseidon.inputs[2] <== hashed_vkey_rec;
    merkle_root = liabilities_pub_outputs['merkle_root']
    hashed_vkey_base = liabilities_pub_outputs["hashed_vkey_liab_base"]
    hashed_vkey_rec = liabilities_pub_outputs["hashed_vkey_liab_rec"]
    return poseidon_hash([hashed_vkey_base, hashed_vkey_rec, merkle_root], 3)


def get_abase_revealed_aggregate_hash(abase_pub_outputs: dict, abase_name: str, print_fn) -> int:
    print_fn(
        f"Inside get_abase_revealed_aggregate_hash. abase_pub_outputs = {abase_pub_outputs}, abase_name = {abase_name}")
    hashed_pub_addrs: int = abase_pub_outputs["hashed_pub_addrs"]
    min_owned_addr_selector: int = abase_pub_outputs["min_owned_addr_selector"]
    max_owned_addr_selector: int = abase_pub_outputs["max_owned_addr_selector"]
    msg_hash: int = abase_pub_outputs["msg_hash"]
    msg_hash_regs: list[int] = list(map(int, int_to_regs(msg_hash)))
    assert len(
        msg_hash_regs) == 4, f"msg_hash_regs should be of length 4, but is {len(msg_hash_regs)}. msg_hash = {msg_hash}, regs = {msg_hash_regs}"
    hashed_vkey_abase_key: str = f"hashed_vkey_{abase_name}_base"
    hashed_vkey_abase: int = abase_pub_outputs[hashed_vkey_abase_key]
    hashed_vkey_anonsetagg: int = abase_pub_outputs["hashed_vkey_anonsetagg"]

    poseidon_inputs: list[int] = []
    for reg in msg_hash_regs:
        poseidon_inputs.append(reg)
    poseidon_inputs.append(hashed_pub_addrs)
    poseidon_inputs.append(min_owned_addr_selector)
    poseidon_inputs.append(max_owned_addr_selector)
    poseidon_inputs.append(hashed_vkey_abase)
    poseidon_inputs.append(hashed_vkey_anonsetagg)

    print_fn(
        f"Inside get_abase_revealed_aggregate_hash. abase_name = {abase_name} poseidon_inputs = {poseidon_inputs}")

    arity = 9  # k (num msg hash regs) + 5
    result = poseidon_hash(poseidon_inputs, arity)
    print_fn(f"Inside get_abase_revealed_aggregate_hash. result = {result}")
    return result


def hash_asset_pub_outputs(assets_pub_outputs: dict, print_fn) -> int:
    abase_names: list[str] = ["eth", "btc", "btc_multi3"]
    agg_hashes: list[int] = [get_abase_revealed_aggregate_hash(
        assets_pub_outputs[abase_name], abase_name, print_fn) for abase_name in abase_names]
    dummy_agg_hash: int = 0

    print_fn(f"Agg Hashes are {agg_hashes}")

    anonsetagg_vkey_hash: int = assets_pub_outputs["anonsetagg_vkey_hash"]
    print_fn(f"anonsetagg_vkey_hash: {anonsetagg_vkey_hash}")
    dummy_vkey_hash: int = assets_pub_outputs["dummy_vkey_hash"]
    print_fn(f"dummy_vkey_hash: {dummy_vkey_hash}")

    poseidon_inputs: list[int] = []
    poseidon_inputs.append(agg_hashes[0])
    poseidon_inputs.append(agg_hashes[1])
    poseidon_inputs.append(agg_hashes[2])
    poseidon_inputs.append(dummy_agg_hash)
    poseidon_inputs.append(anonsetagg_vkey_hash)
    poseidon_inputs.append(anonsetagg_vkey_hash)
    poseidon_inputs.append(anonsetagg_vkey_hash)
    poseidon_inputs.append(dummy_vkey_hash)

    arity = 8
    revealed_agg_hash_assetrec: int = poseidon_hash(poseidon_inputs, arity)
    print_fn(f"revealed_agg_hash_assetrec: {revealed_agg_hash_assetrec}")
    hashed_vkey_asset_rec: int = assets_pub_outputs["assetsrec_vkey_hash"]
    print_fn(f"hashed_vkey_asset_rec: {hashed_vkey_asset_rec}")

    arity = 2
    result: int = poseidon_hash(
        [revealed_agg_hash_assetrec, hashed_vkey_asset_rec], arity)
    print_fn(f"Assets Hash Result: {result}")
    return result


def test_sample_proof_public_outputs_metadata():
    SAMPLE_FILE = "sample_files/sample_proof_public_outputs_metadata.json"
    # Load json into a dict
    with open(SAMPLE_FILE) as f:
        sample_proof_public_outputs_metadata = json.load(f)
    computed_hash: int = hash_pub_outputs(sample_proof_public_outputs_metadata)
    target_hash: int = sample_proof_public_outputs_metadata["target_pubhash"]
    assert computed_hash == target_hash, f"Computed hash {computed_hash} does not match target hash {target_hash}"
    print(
        f"The ZK-solvency proof that uses the target hash {target_hash} did indeed use the public outputs specified by {sample_proof_public_outputs_metadata}")


if __name__ == '__main__':
    test_sample_proof_public_outputs_metadata()
