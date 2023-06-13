"""
ZK-Proof of Solvency consists of two parts. Assets and Liabilities. Ultimately it proves that Assets >= Liabilities for each token.

At a high level, the Liabilities side works as follows:
- The prover uses a list of liabilities where each liability is specified by a tuple (username, nonce, owed balances)
- These liabilities are converted into leaves in a Merkle Tree
- The Merkle Tree is computed inside the ZK-SNARK Liabilities Circuits
- The prover shares the Merkle Tree Root as a revealed public output
- The prover gives a "receipt" to each user, which contains their username, nonce, balances, and a Merkle Branch

Note that the ZK-SNARK Circuits have been constructed in such a way that the prover cannot include dummy liabilities with negative balances.

If you are owed a liability, you should have received a receipt of liability-inclusion from the prover. In order to be valid, this receipt must:
- include the proper accountID, as determined by a unique username and a nonce
- include a valid Merkle Branch which hashes to the publicly revealed Merkle Root associated with this ZK Proof of Solvency
- have the correct balances for the prover's liabilities owed to you

The hash function used here is called Poseidon Hash. It is canonical to use this hash function in ZK-SNARKs because it is very efficient to compute inside the SNARK.
"""

import hashlib
import json

from utils.common import ACCT_PRECISION_DICT, BITCOIN_TOKEN, ETHER_TOKEN, FIELD_SCALAR_BITS, get_balance_orders, int_to_bin, split_into_chunks
from utils.scaling import account_precision_to_proof_precision
from utils.poseidon.poseidon_hash import poseidon_hash


VERBOSE = True

ACCT_BALANCE_BITS = 42
ACCT_BALANCES_PER_ELT = 6
assert (ACCT_BALANCE_BITS * ACCT_BALANCES_PER_ELT <= FIELD_SCALAR_BITS)


def print_verbose(x: str):
    if VERBOSE:
        print(x)


def unformat_balance_value_from_receipt(token: str, balance_str: str) -> int:
    num_decimal_places = None
    if token.upper() == BITCOIN_TOKEN.upper():
        num_decimal_places = ACCT_PRECISION_DICT[BITCOIN_TOKEN]
    elif token.upper() == ETHER_TOKEN.upper():
        num_decimal_places = ACCT_PRECISION_DICT[ETHER_TOKEN]
    else:
        raise Exception(f"Token {token} Not supported")

    decimal_idx = len(balance_str) - num_decimal_places - 1
    assert balance_str[decimal_idx] == ".", f"Balance string {balance_str} is not formatted correctly"
    balance_str = balance_str[:decimal_idx] + balance_str[decimal_idx + 1:]
    return int(balance_str)


def _calculate_account_id(username: str, nonce: str) -> int:
    x = username + nonce
    full_bin_str = int_to_bin(
        int(hashlib.sha512(str.encode(x)).hexdigest(), 16), expected_length=512)
    return int(full_bin_str[:252], 2)


def _pack_balance(chunk: list[int]) -> int:
    mult = 1
    acc = 0
    for balance in chunk:
        acc += mult * balance
        mult <<= ACCT_BALANCE_BITS
    return acc


def get_account_info_packed(account_id: int, balances: list[int]) -> list[int]:
    return ([account_id] +
            [_pack_balance(chunk) for chunk in split_into_chunks(balances, ACCT_BALANCES_PER_ELT)])


def verify_receipt(r: dict, balance_orders=None, log_verbose=True):
    '''
    Inputs: r: Receipt
    Inputs: balance_orders: List of tokens
    Outputs: (correct_account_id, valid_merkle_branch)
    Step 1: Verify hash(username, nonce) = account_id
    Step 2a: Verify account_info_packed is the first preimage
    Step 2b: Verify the last preimage hashes to the merkle root
    Step 2c: Verify each preimage hashes to something in the next preimage (next preimage is of type list)
    '''
    if not balance_orders:
        balance_orders = get_balance_orders()

    # Step 0: Get Merkle arity and leaf hash arity
    merkle_arity: int = int(r['merkle_arity'])
    merkle_leaf_hash_arity: int = int(r['merkle_leaf_hash_arity'])

    # Step 1
    expected_account_id: str = hex(
        _calculate_account_id(r["username"], r["nonce"]))
    correct_account_id: bool = (expected_account_id == r["account_id"])
    if not correct_account_id:
        print_verbose(f"Expected Account ID is: {expected_account_id}")
        print_verbose(f"Actual Account ID is: {r['account_id']}")

    temp: list[str] = r["merkle_branch"].split(";")
    merkle_preimages: list[list[int]] = [
        list(map(int, merkle_preimage.split(","))) for merkle_preimage in temp]
    merkle_branch_valid: bool = True

    # Step 2a
    receipt_account_id: int = int(r["account_id"], 16)
    balance_map = {}
    for balance_entry in r['balances']:
        balance_map[balance_entry['token']] = unformat_balance_value_from_receipt(
            balance_entry['token'], balance_entry['balance'])
    if log_verbose:
        print_verbose(f"Inside Verify Receipt. Balance map is {balance_map}")
        print_verbose(
            f"Inside Verify Receipt. Balance orders is {balance_orders},  and len is {len(balance_orders)}")

    receipt_raw_balances: list[int] = [
        int(balance_map.get(bal_type, 0)) for bal_type in balance_orders]
    receipt_balances: list[int] = []
    for i, balance in enumerate(receipt_raw_balances):
        if balance == 0:
            receipt_balances.append(0)
        else:
            balance_for_proof: int = account_precision_to_proof_precision(
                balance_orders[i], balance)
            receipt_balances.append(balance_for_proof)

    merkle_branch_valid &= get_account_info_packed(
        receipt_account_id, receipt_balances) == merkle_preimages[0]
    if not get_account_info_packed(receipt_account_id, receipt_balances) == merkle_preimages[0]:
        print_verbose("Error in 2a")
        print_verbose(f"Receipt Account ID {receipt_account_id}")
        print_verbose(f"Receipt Balances {receipt_balances}")
        print_verbose(f"Merkle Preimages[0]: {merkle_preimages[0]}")
        print_verbose(
            f"Packed Account Info: {get_account_info_packed(receipt_account_id, receipt_balances)}")

    # Step 2b
    merkle_branch_valid &= poseidon_hash(
        merkle_preimages[-1], merkle_arity) == int(r["merkle_root"])
    if not poseidon_hash(merkle_preimages[-1], merkle_arity) == int(r["merkle_root"]):
        print_verbose(f"Error in 2b")
        print_verbose(
            f"Merkle Preimages[-1]: {merkle_preimages[-1]}, hashes to  {poseidon_hash(merkle_preimages[-1], merkle_arity)}")
        print_verbose(f"Merkle Root: {r['merkle_root']}")

    # Step 2c
    for i in range(len(merkle_preimages)-1):
        arity: int = merkle_arity
        if i == 0:
            arity = merkle_leaf_hash_arity
        curr_hash: int = poseidon_hash(merkle_preimages[i], arity)
        next_preimage_list = merkle_preimages[i+1]
        if curr_hash not in next_preimage_list:
            merkle_branch_valid = False
            print_verbose(
                "----------------------------------------------------------------")
            print_verbose(f"ERROR: receipt invalid")
            print_verbose(f"{i}th preimage is {merkle_preimages[i]}")
            print_verbose(f"Hash is {curr_hash}")
            print_verbose(
                f"Expected hash is something in {next_preimage_list}")
            print_verbose(f"merkle_preimages is {merkle_preimages}")
            print_verbose(
                "----------------------------------------------------------------")

    return (correct_account_id, merkle_branch_valid)


def test_sample_receipt():
    FILENAME = "sample_files/sample-receipt.json"
    with open(FILENAME) as f:
        receipt: dict = json.load(f)
    (correct_account_id, merkle_branch_valid) = verify_receipt(receipt)
    assert correct_account_id, f"Account ID is incorrect"
    assert merkle_branch_valid, f"Merkle branch is invalid"
    print(
        f"SUCCESS!! Receipt is valid, the claimed balance for the claimed accountID was included in a proof whose merkle root was {receipt['merkle_root']}")


if __name__ == '__main__':
    test_sample_receipt()
