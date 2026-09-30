#!/usr/bin/env python3
"""Compatibility entry point: use the corrected, repeatable table generator.

The former one-off text patcher is preserved in before_final_consistency_20260929.
Current narrative edits are maintained directly in main.revised.tex.
"""
from pathlib import Path
import runpy
runpy.run_path(str(Path(__file__).resolve().with_name('generate_tex_20260929.py')), run_name='__main__')
