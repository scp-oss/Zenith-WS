"""Юнит-тест для _parse_tls_client_hello() -- диагностики SNI/ALPN,
добавленной в relay/transparent_relay.py для расследования Android/
Windows (см. CLAUDE.md 'Android MTProto investigation'). Не требует
сети (в отличие от test_transparent_relay_e2e.py) -- чистый разбор
байт, собранных вручную."""
import os
import struct
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'relay'))

from transparent_relay import _parse_tls_client_hello  # noqa: E402


def _build_client_hello(sni: str, alpn=("h2", "http/1.1")) -> bytes:
    session_id = b'\x00' * 32
    cipher_suites = b'\x13\x01\x13\x02'
    comp = b'\x00'

    sni_name = sni.encode()
    sni_entry = b'\x00' + struct.pack('>H', len(sni_name)) + sni_name
    sni_list = struct.pack('>H', len(sni_entry)) + sni_entry
    ext_sni = struct.pack('>H', 0x0000) + struct.pack('>H', len(sni_list)) + sni_list

    alpn_protos = b''.join(bytes([len(p)]) + p.encode() for p in alpn)
    alpn_list = struct.pack('>H', len(alpn_protos)) + alpn_protos
    ext_alpn = struct.pack('>H', 0x0010) + struct.pack('>H', len(alpn_list)) + alpn_list

    extensions = ext_sni + ext_alpn
    ext_block = struct.pack('>H', len(extensions)) + extensions

    body = (b'\x03\x03' + b'\x00' * 32
            + bytes([len(session_id)]) + session_id
            + struct.pack('>H', len(cipher_suites)) + cipher_suites
            + bytes([len(comp)]) + comp
            + ext_block)

    handshake = b'\x01' + len(body).to_bytes(3, 'big') + body
    return b'\x16\x03\x01' + struct.pack('>H', len(handshake)) + handshake


def test_extracts_sni_and_alpn_from_full_client_hello():
    pkt = _build_client_hello("example-masking-domain.com")
    result = _parse_tls_client_hello(pkt)
    assert result == {'sni': 'example-masking-domain.com', 'alpn': ['h2', 'http/1.1']}


def test_truncated_client_hello_returns_none_not_crash():
    pkt = _build_client_hello("example-masking-domain.com")
    assert _parse_tls_client_hello(pkt[:64]) is None


def test_garbage_input_returns_none():
    assert _parse_tls_client_hello(b'\x16\x03\x01\x00\x05abcde') is None
    assert _parse_tls_client_hello(b'\x16\x03') is None
    assert _parse_tls_client_hello(b'not tls at all') is None


def test_client_hello_without_extensions():
    # SSLv3/старый TLS1.0 клиент без extensions вообще -- валидный
    # ClientHello, просто sni/alpn оба None, не должен падать.
    session_id = b''
    cipher_suites = b'\x00\x0a'
    comp = b'\x00'
    body = (b'\x03\x01' + b'\x00' * 32
            + bytes([len(session_id)]) + session_id
            + struct.pack('>H', len(cipher_suites)) + cipher_suites
            + bytes([len(comp)]) + comp)
    handshake = b'\x01' + len(body).to_bytes(3, 'big') + body
    pkt = b'\x16\x03\x01' + struct.pack('>H', len(handshake)) + handshake
    assert _parse_tls_client_hello(pkt) == {'sni': None, 'alpn': None}


if __name__ == '__main__':
    test_extracts_sni_and_alpn_from_full_client_hello()
    test_truncated_client_hello_returns_none_not_crash()
    test_garbage_input_returns_none()
    test_client_hello_without_extensions()
    print("PASS")
