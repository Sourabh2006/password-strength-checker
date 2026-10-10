"""
Main Application Launcher for PassGuard Password Strength Checker & Auditing Engine.

Usage:
  python app.py             # Launches the Native Desktop GUI (default)
  python app.py --gui       # Explicitly launch Desktop GUI
  python app.py --web       # Launches Local Web GUI Dashboard (in browser)
  python app.py --cli       # Launches Interactive Secure Terminal CLI
  python app.py --demo      # Runs Benchmark Auditing Suite
  python app.py --test      # Runs Unit Test Suite
"""

import sys
import os
import argparse

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))


def main():
    parser = argparse.ArgumentParser(
        description="PassGuard: Credential Auditing & Entropy Analysis Engine",
        formatter_class=argparse.RawTextHelpFormatter,
    )
    group = parser.add_mutually_exclusive_group()
    group.add_argument(
        "--gui",
        action="store_true",
        help="Launch the native desktop GUI (Default mode)",
    )
    group.add_argument(
        "--web",
        action="store_true",
        help="Launch the local Web GUI dashboard in default browser",
    )
    group.add_argument(
        "--cli",
        action="store_true",
        help="Run interactive secure terminal CLI mode",
    )
    group.add_argument(
        "--demo",
        action="store_true",
        help="Run benchmark suite on weak, moderate, and robust credentials",
    )
    group.add_argument(
        "--test",
        action="store_true",
        help="Run full unit test suite",
    )
    parser.add_argument(
        "-p", "--password",
        type=str,
        default=None,
        help="Password string to evaluate directly via CLI (for automated audits)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output evaluation in JSON format (CLI mode)",
    )

    args = parser.parse_args()

    # Dispatch based on arguments
    if args.web:
        from web_gui import run_web_server
        run_web_server()
    elif args.test:
        import unittest
        loader = unittest.TestLoader()
        suite = loader.discover("tests")
        runner = unittest.TextTestRunner(verbosity=2)
        res = runner.run(suite)
        sys.exit(0 if res.wasSuccessful() else 1)
    elif args.demo:
        from cli import run_benchmark_demo
        run_benchmark_demo()
    elif args.cli or args.password is not None or args.json:
        from cli import main as cli_main
        cli_main()
    else:
        # Default behavior: Launch Native Desktop GUI
        try:
            from gui import main as gui_main
            gui_main()
        except Exception as e:
            print(f"[Warning] Could not initialize graphical display ({e}).")
            print("Falling back to Interactive CLI mode...\n")
            from cli import main as cli_main
            cli_main()


if __name__ == "__main__":
    main()
