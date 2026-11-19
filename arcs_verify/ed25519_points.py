"""Strict edwards25519 point validation for the pilot trust bundle.

Canonical decoding per RFC 8032 section 5.1.3 and an exact-order-L check, used to
refuse a bundle public key that is not a valid prime-order Ed25519 point. Pure Python
arithmetic with no external dependency; used for validation only, never for signing.

Derived from the arcs-verify-dev module of the same name (blob 0a12874e). The point
arithmetic and ``decode_point`` / ``exact_order_l`` are unchanged. The dev module's
verifier fault-mapping helpers (``public_key_fault`` and ``signature_point_fault``)
are not carried: nothing on this line calls them, and their return strings are
verifier failure codes that this line does not emit. The ``ValueError`` messages are
human-readable text, not failure codes: callers catch ``ValueError`` and ignore it.

The curve constants, ``_recover_x``, ``point_add`` and ``point_mul`` follow the
reference implementation in RFC 8032 section 6 (S. Josefsson, I. Liusvaara), which
is an IETF Code Component and carries this notice:

    Copyright (c) 2017 IETF Trust and the persons identified as authors of the
    code. All rights reserved.

    Redistribution and use in source and binary forms, with or without
    modification, is permitted pursuant to, and subject to the license terms
    contained in, the Simplified BSD License set forth in Section 4.c of the IETF
    Trust's Legal Provisions Relating to IETF Documents
    (https://trustee.ietf.org/license-info).
"""

p = 2**255 - 19
L = 2**252 + 27742317777372353535851937790883648493
d = -121665 * pow(121666, p - 2, p) % p
I = pow(2, (p - 1) // 4, p)


def _inv(x: int) -> int:
    return pow(x % p, p - 2, p)


def _recover_x(y: int, sign: int) -> int:
    xx = (y * y - 1) * _inv(d * y * y + 1) % p
    x = pow(xx, (p + 3) // 8, p)
    if (x * x - xx) % p != 0:
        x = x * I % p
    if (x * x - xx) % p != 0:
        raise ValueError("point is not on the curve")
    if (x & 1) != sign:
        x = (p - x) % p
    if x == 0 and sign == 1:
        raise ValueError("negative zero x coordinate")
    return x


def decode_point(encoded: bytes) -> tuple:
    """Decode a 32-octet point, rejecting non-canonical encodings."""
    if len(encoded) != 32:
        raise ValueError("encoding is not 32 octets")
    sign = encoded[31] >> 7
    y = int.from_bytes(encoded, "little") & ((1 << 255) - 1)
    if y >= p:
        raise ValueError("non-canonical y coordinate")
    x = _recover_x(y, sign)
    if (-x * x + y * y - 1 - d * x * x * y * y) % p != 0:
        raise ValueError("point is not on the curve")
    return (x, y, 1, x * y % p)


IDENT = (0, 1, 1, 0)


def point_add(P: tuple, Q: tuple) -> tuple:
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % p
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % p
    C = 2 * P[3] * Q[3] * d % p
    D = 2 * P[2] * Q[2] % p
    E, F, G, H = B - A, D - C, D + C, B + A
    return (E * F % p, G * H % p, F * G % p, E * H % p)


def point_mul(s: int, P: tuple) -> tuple:
    Q = IDENT
    while s > 0:
        if s & 1:
            Q = point_add(Q, P)
        P = point_add(P, P)
        s >>= 1
    return Q


def _affine(P: tuple) -> tuple:
    z = _inv(P[2])
    return (P[0] * z % p, P[1] * z % p)


def same_point(P: tuple, Q: tuple) -> bool:
    return _affine(P) == _affine(Q)


def exact_order_l(P: tuple) -> bool:
    """True iff P has order exactly L (prime-order subgroup, not identity)."""
    return not same_point(P, IDENT) and same_point(point_mul(L, P), IDENT)
