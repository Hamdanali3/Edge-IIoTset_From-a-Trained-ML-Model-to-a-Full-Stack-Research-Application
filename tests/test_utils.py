import unittest
import sys
import os

# Allow running tests from the repo root or from inside tests/
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from utils import check_overfitting, normalize_score


class TestCheckOverfitting(unittest.TestCase):
    def test_no_overfitting(self):
        gap, is_overfitting = check_overfitting(train_acc=0.90, test_acc=0.88)
        self.assertAlmostEqual(gap, 0.02, places=4)
        self.assertFalse(is_overfitting)

    def test_overfitting_detected(self):
        gap, is_overfitting = check_overfitting(train_acc=0.99, test_acc=0.80)
        self.assertAlmostEqual(gap, 0.19, places=4)
        self.assertTrue(is_overfitting)

    def test_custom_threshold(self):
        gap, is_overfitting = check_overfitting(train_acc=0.95, test_acc=0.92, threshold=0.01)
        self.assertTrue(is_overfitting)

    def test_invalid_train_acc(self):
        with self.assertRaises(ValueError):
            check_overfitting(train_acc=1.5, test_acc=0.80)

    def test_invalid_test_acc(self):
        with self.assertRaises(ValueError):
            check_overfitting(train_acc=0.90, test_acc=-0.1)


class TestNormalizeScore(unittest.TestCase):
    def test_normalize_score(self):
        self.assertEqual(normalize_score(50, 100), 0.5)

    def test_full_score(self):
        self.assertEqual(normalize_score(100, 100), 1.0)

    def test_invalid_maximum(self):
        with self.assertRaises(ValueError):
            normalize_score(50, 0)


if __name__ == "__main__":
    unittest.main()
