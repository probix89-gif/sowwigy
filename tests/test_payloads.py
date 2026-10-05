from swiggy_hunter.scanner.payloads import PAYLOADS, load_payload


def test_sets_exist():
    for k in ("numeric_tamper", "coupon_shape", "currency", "quantity"):
        assert k in PAYLOADS and PAYLOADS[k]


def test_load():
    p = load_payload("numeric_tamper")
    assert "-1" in p
