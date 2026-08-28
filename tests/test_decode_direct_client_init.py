"""Юнит-тесты для _decode_direct_client_init() -- в частности, за
изменение 2026-08-28 (см. CLAUDE.md 'Android MTProto investigation'):
proto_tag распознан, но dc_id вне _REAL_DC_IDS больше НЕ отбрасывается
целиком -- релеится с _FALLBACK_DC, помечено dc_reliable=False. Раньше
это был единственный случай, отличавший реальные (но с "чужим" dc_id)
клиентские пакеты Android/Windows от настоящего мусора, и жёсткий
отброс ронял их в SYN-заблокированный passthrough вместо WS-моста."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'prober'))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'relay'))

from proto import build_obfuscated_init, PROTO_TAG_INTERMEDIATE  # noqa: E402
from transparent_relay import _decode_direct_client_init, _FALLBACK_DC  # noqa: E402


def test_valid_dc_is_reliable():
    packet = build_obfuscated_init(2, PROTO_TAG_INTERMEDIATE)
    result = _decode_direct_client_init(packet)
    assert result is not None
    dc, is_media, proto_tag, _prekey_iv, dc_reliable = result
    assert dc == 2
    assert is_media is False
    assert proto_tag == PROTO_TAG_INTERMEDIATE
    assert dc_reliable is True


def test_media_flag_and_test_dc_still_reliable():
    packet = build_obfuscated_init(-10004, PROTO_TAG_INTERMEDIATE)
    result = _decode_direct_client_init(packet)
    assert result is not None
    dc, is_media, _proto_tag, _prekey_iv, dc_reliable = result
    assert dc == 10004
    assert is_media is True
    assert dc_reliable is True


def test_out_of_range_dc_relayed_with_fallback_not_rejected():
    # Эмулирует живой случай 2026-08-28: proto_tag настоящий, но
    # dc_idx -- число вне реального диапазона Telegram (Android/
    # Windows через VLESS). Раньше это давало None (отброс в
    # passthrough); теперь -- фолбэк-DC и dc_reliable=False, но
    # НЕ None.
    packet = build_obfuscated_init(12965, PROTO_TAG_INTERMEDIATE)
    result = _decode_direct_client_init(packet)
    assert result is not None, "не должно отбрасываться целиком -- proto_tag настоящий"
    dc, is_media, proto_tag, _prekey_iv, dc_reliable = result
    assert dc == _FALLBACK_DC
    assert proto_tag == PROTO_TAG_INTERMEDIATE
    assert dc_reliable is False


def test_unrecognized_proto_tag_still_rejected():
    # Совершенно случайные байты -- НЕ должны декодироваться как
    # MTProto хоть с каким-то dc. Это единственный случай, где
    # результат обязан быть None.
    garbage = bytes(range(64))
    result = _decode_direct_client_init(garbage)
    assert result is None


if __name__ == '__main__':
    failures = 0
    for name, fn in list(globals().items()):
        if name.startswith('test_') and callable(fn):
            try:
                fn()
                print(f"PASS {name}")
            except AssertionError as e:
                failures += 1
                print(f"FAIL {name}: {e}")
    print(f"\n{'ALL PASSED' if not failures else f'{failures} FAILED'}")
    raise SystemExit(1 if failures else 0)
