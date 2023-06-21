from dataclasses import dataclass
from py_ecc.fields import (
    bn128_FQ as FQ,
    bn128_FQ2 as FQ2,
    bn128_FQ12 as FQ12,
)
from py_ecc.bn128 import (
    bn128_curve as curve,
    bn128_pairing as pairing
)

VERBOSE = True

# Curve is y**2 = x**3 + 3
b = FQ(3)
# Twisted curve over FQ**2
b2 = FQ2([3, 0]) / FQ2([9, 1])

P = 21888242871839275222246405745257275088696311157297823662689037894645226208583


def on_curve_check(pt, b) -> bool:
    """
    Check that a point is on the curve defined by y**2 == x**3 + b
    """
    if not pt:
        return True
    x, y = pt
    return y**2 - x**3 == b


def print_verbose(x):
    if VERBOSE:
        print(x)


class G1Point:
    def __init__(self, point: tuple[int, int]):
        self.point: tuple[FQ, FQ] = (FQ(point[0]), FQ(point[1]))
        assert on_curve_check(
            self.point, b), f"point {point} is not on curve.."

    def __repr__(self) -> str:
        return repr(self.point)


def negate_g1(p1: G1Point) -> G1Point:
    return G1Point(curve.neg(p1.point))


def add_g1(p1: G1Point, p2: G1Point) -> G1Point:
    return G1Point(curve.add(p1.point, p2.point))


def scalar_mult_g1(scalar: int, p1: G1Point) -> G1Point:
    return G1Point(curve.multiply(p1.point, scalar))


class G2Point:
    def __init__(self, point: tuple[tuple[int, int], tuple[int, int]] = None, fq2_point: tuple[FQ2, FQ2] = None):
        if point:
            x: FQ2 = FQ2(point[0])
            y: FQ2 = FQ2(point[1])
            self.point: tuple[FQ2, FQ2] = (x, y)
        else:
            assert fq2_point, f"Must provide either a point or an fq2_point"
            self.point: tuple[FQ2, FQ2] = fq2_point
        assert on_curve_check(
            self.point, b2), f"point {point} is not on curve.."

    def __repr__(self) -> str:
        return repr(self.point)


def add_g2(p1: G2Point, p2: G2Point) -> G2Point:
    return G2Point(curve.add(p1.point, p2.point))


def scalar_mult_g2(scalar: int, p: G2Point) -> G2Point:
    temp = curve.multiply(p.point, scalar)
    return G2Point(fq2_point=temp)


def pairing_help(p1: G1Point, p2: G2Point) -> FQ12:
    return pairing.pairing(p2.point, p1.point)


def pairings_help(p1: list[G1Point], p2: list[G2Point]):
    """
    Given a list of G1 points and a list of G2 points, compute the product of the pairings
    and return True if their product is one.
    """
    assert len(p1) == len(p2), f"pairing-lengths-failed"
    results: list[FQ12] = []
    for i in range(len(p1)):
        results.append(pairing_help(p1[i], p2[i]))

    result = results[0]
    for i in range(1, len(results)):
        result = result * results[i]

    return result == FQ12.one()


def test_pairing():
    #### THIS TEST FAILS RIGHT NOW ###
    # Generator for curve over FQ
    G1 = G1Point((1, 2))
    # Generator for twisted curve over FQ2
    G2 = G2Point((
        (
            10857046999023057135944570762232829481370756359578518086990519993285655852781,
            11559732032986387107991004021392285783925812861821192530917403151452391805634,
        ),
        (
            8495653923123431417604973247489272438418190587263600148770280649306958101930,
            4082367875863433681332203403145435568316851327593401208105741076214120093531,
        ),
    ))

    a: int = 7
    b: int = 29
    G2a: G2Point = scalar_mult_g2(a, G2)
    G2b: G2Point = scalar_mult_g2(b, G2)
    G2c: G2Point = scalar_mult_g2(a+b, G2)

    # Check that e(G1, G2c) == e(G1, G2a) * e(G1, G2b)
    # we'll denote as resc, resa, resb
    resc: FQ12 = pairing_help(G1, G2c)
    resb: FQ12 = pairing_help(G1, G2b)
    resa: FQ12 = pairing_help(G1, G2a)

    res_rhs: FQ12 = resb * resa
    assert resc == res_rhs, f"pairing-test-failed"


if __name__ == "__main__":
    test_pairing()
