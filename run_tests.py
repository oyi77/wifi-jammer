#!/usr/bin/env python3
"""
Test runner for WiFi Jammer Tool.
"""

import unittest
import sys
import os

# Add the project root to the Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def run_tests():
    """Run all tests."""
    print("🧪 Running WiFi Jammer Tool Tests")
    print("=" * 50)

    # Discover and run tests
    loader = unittest.TestLoader()
    start_dir = os.path.join(os.path.dirname(__file__), "tests")
    suite = loader.discover(start_dir, pattern="test_*.py")

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Print summary
    print("\n" + "=" * 50)
    if result.wasSuccessful():
        print("✅ All tests passed!")
        return 0
    else:
        print(
            f"❌ {len(result.failures)} tests failed, {len(result.errors)} tests had errors"
        )
        return 1


if __name__ == "__main__":
    sys.exit(run_tests())
