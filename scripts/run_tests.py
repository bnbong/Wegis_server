#!/usr/bin/env python3
# --------------------------------------------------------------------------
# Test runner script
#
# @author bnbong bbbong9@gmail.com
# --------------------------------------------------------------------------
import subprocess
import sys
import os


def run_tests():
    """Test execution function"""
    # Move to project root directory
    project_root = os.path.dirname(os.path.abspath(__file__))
    os.chdir(project_root)

    print("🧪 Running tests for Wegis Server...")
    print("=" * 50)

    # Run unit tests
    print("\n📋 Running unit tests...")
    result_unit = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "tests/test_domain_checker.py",
            "tests/test_analyzer.py",
            "-v",
            "--tb=short",
        ],
        capture_output=True,
        text=True,
    )

    if result_unit.returncode == 0:
        print("✅ Unit tests passed!")
    else:
        print("❌ Unit tests failed!")
        print(result_unit.stdout)
        print(result_unit.stderr)

    # Run API tests
    print("\n🌐 Running API tests...")
    result_api = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "tests/test_api_routes.py",
            "-v",
            "--tb=short",
        ],
        capture_output=True,
        text=True,
    )

    if result_api.returncode == 0:
        print("✅ API tests passed!")
    else:
        print("❌ API tests failed!")
        print(result_api.stdout)
        print(result_api.stderr)

    # Run integration tests
    print("\n🔗 Running integration tests...")
    result_integration = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "tests/test_integration.py",
            "-v",
            "--tb=short",
            "-m",
            "integration",
        ],
        capture_output=True,
        text=True,
    )

    if result_integration.returncode == 0:
        print("✅ Integration tests passed!")
    else:
        print("❌ Integration tests failed!")
        print(result_integration.stdout)
        print(result_integration.stderr)

    # Summary of all results
    print("\n" + "=" * 50)
    total_failed = (
        result_unit.returncode + result_api.returncode + result_integration.returncode
    )

    if total_failed == 0:
        print("🎉 All tests passed!")
        return 0
    else:
        print(f"💥 {total_failed} test suite(s) failed!")
        return 1


if __name__ == "__main__":
    exit_code = run_tests()
    sys.exit(exit_code)
