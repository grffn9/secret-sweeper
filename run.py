"""Run secret-sweep from anywhere without installing it:  python path/to/run.py scan <target>"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from secretsweep.__main__ import run  # noqa: E402

run()
