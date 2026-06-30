import os
import unittest

import warpcrypto


class TestBindings(unittest.TestCase):
    def test_all_functions_present(self):
        required = [
            "ige256_encrypt", "ige256_decrypt",
            "ctr256_encrypt", "ctr256_decrypt",
            "kdf", "pack_message", "unpack_message",
        ]
        for name in required:
            self.assertTrue(hasattr(warpcrypto, name), f"Missing: {name}")


class TestIGE256(unittest.TestCase):
    def test_ige256_roundtrip(self):
        key = os.urandom(32)
        iv = os.urandom(32)
        for size in [16, 32, 48, 64, 128, 1024, 1048576]:
            pt = os.urandom(size)
            ct = warpcrypto.ige256_encrypt(pt, key, iv)
            dec = warpcrypto.ige256_decrypt(ct, key, iv)
            self.assertEqual(dec, pt, f"IGE roundtrip failed at size={size}")

    def test_ige256_encrypt_wrong_key_size(self):
        with self.assertRaises(ValueError):
            warpcrypto.ige256_encrypt(b"\x00" * 16, b"\x00" * 31, b"\x00" * 32)

    def test_ige256_encrypt_wrong_iv_size(self):
        with self.assertRaises(ValueError):
            warpcrypto.ige256_encrypt(b"\x00" * 16, b"\x00" * 32, b"\x00" * 31)

    def test_ige256_decrypt_wrong_key_size(self):
        with self.assertRaises(ValueError):
            warpcrypto.ige256_decrypt(b"\x00" * 16, b"\x00" * 31, b"\x00" * 32)

    def test_ige256_decrypt_wrong_iv_size(self):
        with self.assertRaises(ValueError):
            warpcrypto.ige256_decrypt(b"\x00" * 16, b"\x00" * 32, b"\x00" * 31)


class TestCTR256(unittest.TestCase):
    def test_ctr256_roundtrip(self):
        key = os.urandom(32)
        for size in [1, 15, 16, 17, 31, 32, 100, 1024, 1048576]:
            pt = os.urandom(size)
            orig_iv = bytearray(os.urandom(16))

            iv1 = bytearray(orig_iv)
            enc = warpcrypto.ctr256_encrypt(pt, key, iv1, bytearray(1))

            iv2 = bytearray(orig_iv)
            dec = warpcrypto.ctr256_decrypt(enc, key, iv2, bytearray(1))

            self.assertEqual(dec, pt, f"CTR roundtrip failed at size={size}")

    def test_ctr256_identity(self):
        key = os.urandom(32)
        for size in [1, 15, 16, 31, 100]:
            pt = os.urandom(size)
            orig_iv = bytearray(os.urandom(16))
            iv1 = bytearray(orig_iv)
            double = warpcrypto.ctr256_encrypt(
                warpcrypto.ctr256_encrypt(pt, key, iv1, bytearray(1)),
                key, bytearray(orig_iv), bytearray(1),
            )
            self.assertEqual(double, pt, f"CTR double encrypt != original at size={size}")

    def test_ctr256_state_propagation(self):
        key = os.urandom(32)
        for s1, s2 in [(10, 10), (20, 10), (5, 20), (16, 16), (100, 50)]:
            d1 = os.urandom(s1)
            d2 = os.urandom(s2)
            orig_iv = bytearray(os.urandom(16))

            iv_t = bytearray(orig_iv)
            st_t = bytearray(1)

            iv_w = bytearray(orig_iv)
            st_w = bytearray(1)

            r1_w = warpcrypto.ctr256_encrypt(d1, key, iv_w, st_w)
            r2_w = warpcrypto.ctr256_encrypt(d2, key, iv_w, st_w)

            self.assertIsInstance(r1_w, bytes)
            self.assertIsInstance(r2_w, bytes)
            self.assertEqual(len(r1_w), s1)
            self.assertEqual(len(r2_w), s2)

    def test_ctr256_iv_mutated(self):
        key = os.urandom(32)
        iv = bytearray(os.urandom(16))
        iv_original = list(iv)
        _ = warpcrypto.ctr256_encrypt(b"\x00" * 32, key, iv, bytearray(1))
        self.assertNotEqual(list(iv), iv_original, "IV should be mutated after CTR call")

    def test_ctr256_state_mutated(self):
        key = os.urandom(32)
        state = bytearray(1)
        _ = warpcrypto.ctr256_encrypt(b"\x00" * 10, key, bytearray(os.urandom(16)), state)
        self.assertNotEqual(list(state), [0], "State should be mutated after CTR call")


class TestKDF(unittest.TestCase):
    def test_kdf_returns_key_iv(self):
        auth_key = os.urandom(256)
        msg_key = os.urandom(16)
        for outgoing in [True, False]:
            k, iv = warpcrypto.kdf(auth_key, msg_key, outgoing)
            self.assertEqual(len(k), 32)
            self.assertEqual(len(iv), 32)

    def test_kdf_outgoing_vs_incoming(self):
        auth_key = os.urandom(256)
        msg_key = os.urandom(16)
        k_out, iv_out = warpcrypto.kdf(auth_key, msg_key, True)
        k_in, iv_in = warpcrypto.kdf(auth_key, msg_key, False)
        self.assertNotEqual(k_out, k_in)
        self.assertNotEqual(iv_out, iv_in)


class TestPackMessage(unittest.TestCase):
    AUTH_KEY = bytes(range(256))
    AUTH_KEY_ID = __import__("hashlib").sha256(AUTH_KEY).digest()[-8:]
    SESSION_ID = os.urandom(8)

    def test_pack_has_auth_key_id(self):
        packed = warpcrypto.pack_message(b"test", 0, self.SESSION_ID, self.AUTH_KEY, self.AUTH_KEY_ID)
        self.assertEqual(packed[:8], self.AUTH_KEY_ID)

    def test_pack_has_msg_key(self):
        packed = warpcrypto.pack_message(b"test", 0, self.SESSION_ID, self.AUTH_KEY, self.AUTH_KEY_ID)
        self.assertEqual(len(packed[8:24]), 16)

    def test_pack_16_byte_aligned(self):
        packed = warpcrypto.pack_message(b"test", 0, self.SESSION_ID, self.AUTH_KEY, self.AUTH_KEY_ID)
        self.assertEqual((len(packed) - 8) % 16, 0)

    def test_pack_unique(self):
        results = set()
        for _ in range(10):
            p = bytes(warpcrypto.pack_message(b"test", 0, self.SESSION_ID, self.AUTH_KEY, self.AUTH_KEY_ID))
            results.add(p)
        self.assertEqual(len(results), 10)

    def test_pack_various_sizes(self):
        for size in [0, 1, 16, 100, 1000]:
            payload = os.urandom(size)
            packed = warpcrypto.pack_message(payload, 0, self.SESSION_ID, self.AUTH_KEY, self.AUTH_KEY_ID)
            self.assertGreater(len(packed), 24)
            self.assertEqual((len(packed) - 8) % 16, 0)


class TestUnpackMessage(unittest.TestCase):
    AUTH_KEY = bytes(range(256))
    AUTH_KEY_ID = __import__("hashlib").sha256(AUTH_KEY).digest()[-8:]
    SESSION_ID = os.urandom(8)

    def test_unpack_invalid_auth_key_id(self):
        packed = warpcrypto.pack_message(b"test", 0, self.SESSION_ID, self.AUTH_KEY, self.AUTH_KEY_ID)
        bad_key_id = os.urandom(8)
        with self.assertRaises(ValueError):
            warpcrypto.unpack_message(packed, self.SESSION_ID, self.AUTH_KEY, bad_key_id)

    def test_unpack_invalid_session_id(self):
        packed = warpcrypto.pack_message(b"test", 0, self.SESSION_ID, self.AUTH_KEY, self.AUTH_KEY_ID)
        bad_sid = os.urandom(8)
        with self.assertRaises(ValueError):
            warpcrypto.unpack_message(packed, bad_sid, self.AUTH_KEY, self.AUTH_KEY_ID)

    def test_unpack_too_short(self):
        with self.assertRaises(ValueError):
            warpcrypto.unpack_message(b"", self.SESSION_ID, self.AUTH_KEY, self.AUTH_KEY_ID)


if __name__ == "__main__":
    unittest.main()
