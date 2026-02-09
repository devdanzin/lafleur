"""Unit tests for the bloom filter hash implementation in driver.py."""

import unittest

from lafleur.driver import _PyBloomFilter, check_bloom, BLOOM_WORDS


class TestCheckBloom(unittest.TestCase):
    """Tests for the check_bloom function."""

    def _make_bloom(self, words: list[int] | None = None) -> _PyBloomFilter:
        """Create a bloom filter with specified word values."""
        bloom = _PyBloomFilter()
        if words:
            for i, w in enumerate(words):
                bloom.bits[i] = w
        return bloom

    def test_empty_bloom_rejects_everything(self):
        """An all-zeros bloom filter should reject any address."""
        bloom = self._make_bloom([0] * BLOOM_WORDS)
        for addr in [0, 1, 42, 12345, 0xDEADBEEF, id(object())]:
            self.assertFalse(
                check_bloom(bloom, addr),
                f"Empty bloom filter should reject address {addr:#x}",
            )

    def test_full_bloom_accepts_everything(self):
        """An all-ones bloom filter should accept any address."""
        bloom = self._make_bloom([0xFFFFFFFF] * BLOOM_WORDS)
        for addr in [0, 1, 42, 12345, 0xDEADBEEF, id(object())]:
            self.assertTrue(
                check_bloom(bloom, addr),
                f"Full bloom filter should accept address {addr:#x}",
            )

    def test_deterministic_results(self):
        """Same address against same filter should always give same result."""
        bloom = self._make_bloom([0xAAAAAAAA] * BLOOM_WORDS)
        addr = 0x12345678
        result1 = check_bloom(bloom, addr)
        result2 = check_bloom(bloom, addr)
        self.assertEqual(result1, result2)

    def test_different_addresses_can_differ(self):
        """A sparse bloom filter should reject some addresses and accept others.

        With a sparse filter, most addresses should be rejected. We test
        enough addresses to be confident that check_bloom is actually
        computing hash probes rather than returning a constant.
        """
        bloom = self._make_bloom([0x00000001] + [0] * (BLOOM_WORDS - 1))

        results = set()
        for addr in range(1000, 1100):
            results.add(check_bloom(bloom, addr))

        self.assertIn(False, results, "Sparse bloom filter should reject some addresses")

    def test_single_bit_filter(self):
        """A filter with a single bit set should be very selective."""
        bloom = self._make_bloom([0] * BLOOM_WORDS)
        bloom.bits[0] = 1  # Only bit 0 of word 0

        reject_count = 0
        total = 200
        for addr in range(total):
            if not check_bloom(bloom, addr):
                reject_count += 1

        # With only 1 of 256 bits set, and K=6 probes, almost everything
        # should be rejected. We expect >90% rejection rate.
        self.assertGreater(
            reject_count / total,
            0.9,
            f"Single-bit filter should reject most addresses, got {reject_count}/{total}",
        )

    def test_real_object_address(self):
        """Test with an actual Python object's address."""
        obj = object()
        addr = id(obj)

        full_bloom = self._make_bloom([0xFFFFFFFF] * BLOOM_WORDS)
        self.assertTrue(check_bloom(full_bloom, addr))

        empty_bloom = self._make_bloom([0] * BLOOM_WORDS)
        self.assertFalse(check_bloom(empty_bloom, addr))


if __name__ == "__main__":
    unittest.main()
