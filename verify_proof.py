"""
This code accomplishes what the Smart Contract located at: https://etherscan.io/address/0xa3965810538b8b688e3ca06c2f188b74b397854a#code
does.
Given:
- A ZK-SNARK Proof (pi_a, pi_b, pi_c)
- A Verifying Key
- Public Inputs (which for ZeKnow Solv is always two Public Inputs)

Return:
- True if the proof is valid for the given public input + verifying key
- False otherwise

Terminology Note: you may see the terms public inputs and public outputs used in confusing ways. Public Inputs is a technical term that
operates at the level of a ZK-SNARK Proof. It refers to the first part of the witness that must be set correctly in order for a SNARK proof object's
mathematical checks be valid. In the ZeKnow Solv Protocol, this Public Inputs is always two values. The first is always the value "1". The second is an aggregated hash of other values.

The public outputs are the revealed outputs of the ZeKnow Solv Protocol that can be hashed together in a specific way in order to construct the second public input.

Since the first public input is always the constant "1", sometimes we refer to "the public input" as really the second public input. 
"""


from dataclasses import dataclass
import json
from utils.bn254_helpers import G1Point, G2Point, add_g1, negate_g1, pairings_help, scalar_mult_g1

VERBOSE = True


def print_verbose(x):
    if VERBOSE:
        print(x)


@dataclass
class VerifyingKey:
    alpha1: G1Point
    beta2: G2Point
    gamma2: G2Point
    delta2: G2Point
    IC0: G1Point
    IC1: G1Point


@dataclass
class Proof:
    A: G1Point
    B: G2Point
    C: G1Point


def verify(input: int, proof: Proof, vk: VerifyingKey) -> bool:
    # print_verbose(f"Inside verify with input={input}, proof={proof}, vk={vk}")
    snark_scalar_field: int = 21888242871839275222246405745257275088548364400416034343698204186575808495617
    assert input < snark_scalar_field, "public input is too large"
    temp1: G1Point = vk.IC0  # 1 * IC0
    temp2: G1Point = scalar_mult_g1(input, vk.IC1)  # input * IC1
    vk_x: G1Point = add_g1(temp1, temp2)  # 1 * IC0 + input * IC1

    # [-A], [alpha1], [vk_x], [C]
    p1s: list[G1Point] = [negate_g1(proof.A), vk.alpha1, vk_x, proof.C]
    # p1s: list[G1Point] = [proof.A, vk.alpha1, vk_x, proof.C]
    p2s: list[G2Point] = [proof.B, vk.beta2, vk.gamma2, vk.delta2]
    return pairings_help(p1s, p2s)


def raw_to_G1(raw: list[str, str]) -> G1Point:
    assert len(raw) == 2, "Raw G1Point must be a list of length 2"
    converted: tuple[int, int] = (int(raw[0]), int(raw[1]))
    return G1Point(converted)


def raw_to_G2(raw: list[list[str, str], list[str, str]]) -> G2Point:
    assert len(raw) == 2, "Raw G2Point must be a list of length 2"
    assert len(raw[0]) == 2, "Raw G2Point must be a list of length 2"
    assert len(raw[1]) == 2, "Raw G2Point must be a list of length 2"
    converted: list[tuple[int, int]] = [(int(item[1]), int(item[0]))
                                        for item in raw]
    converted = tuple(converted)
    return G2Point(converted)


def parse_proof(filename: str) -> Proof:
    with open(filename) as f:
        proof_dict: dict = json.load(f)
    a: G1Point = raw_to_G1(proof_dict["pi_a"])
    b: G2Point = raw_to_G2(proof_dict["pi_b"])
    c: G1Point = raw_to_G1(proof_dict["pi_c"])
    proof: Proof = Proof(a, b, c)
    return proof


def parse_vk(filename: str) -> VerifyingKey:
    with open(filename) as f:
        vk_dict: dict = json.load(f)

    alpha1: G1Point = raw_to_G1(vk_dict["vk_alpha_1"])
    beta2: G2Point = raw_to_G2(vk_dict["vk_beta_2"])
    gamma2: G2Point = raw_to_G2(vk_dict["vk_gamma_2"])
    delta2: G2Point = raw_to_G2(vk_dict["vk_delta_2"])
    ic0: G1Point = raw_to_G1(vk_dict["IC"][0])
    ic1: G1Point = raw_to_G1(vk_dict["IC"][1])
    vk: VerifyingKey = VerifyingKey(alpha1, beta2, gamma2, delta2, ic0, ic1)
    return vk


def parse_pub_input(filename: str) -> int:
    with open(filename) as f:
        outputs: dict = json.load(f)
    result: int = outputs["target_pubhash"]
    return result


def main():
    PROOF_FILENAME: str = "sample_files/sample_proof.json"
    VK_FILENAME: str = "sample_files/sample_verifying_key.json"
    PUBLIC_OUTPUTS_FILENAME: str = "sample_files/sample_public_outputs.json"
    proof: Proof = parse_proof(PROOF_FILENAME)
    vk: VerifyingKey = parse_vk(VK_FILENAME)
    public_input: int = parse_pub_input(PUBLIC_OUTPUTS_FILENAME)
    result: bool = verify(public_input, proof, vk)
    print(f"verification success: {result}")
    assert result, f"Verification failed!"


if __name__ == "__main__":
    main()
