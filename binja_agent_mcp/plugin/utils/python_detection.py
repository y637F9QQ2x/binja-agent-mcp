# This file is part of binja-agent-mcp, a modified version of "Binary Ninja MCP" by fosdickio and
# CX330Blake (https://github.com/fosdickio/binary_ninja_mcp, upstream commit
# d8a2709df69ff475d6be6366c2eec733663b008b, 2025-12-16).
# Copyright (C) 2025 fosdickio, CX330Blake
# Copyright (C) 2026 Kazuma Matsumoto
# Modified by Kazuma Matsumoto between 2026-10-14 and 2026-11-18; see NOTICE.md and CHANGES-FROM-UPSTREAM.md.
# SPDX-License-Identifier: GPL-3.0-or-later
# This program comes with ABSOLUTELY NO WARRANTY; see the LICENSE file for details.
"""
Shared utilities for Python interpreter detection and virtual environment management.
"""

import os
import sys
import subprocess
import venv
from typing import List

# No child process ever opens a console window.
_NO_WINDOW = getattr(subprocess, 'CREATE_NO_WINDOW', 0)


def get_system_python_candidates() -> List[str]:
    """Get a list of candidate system Python paths for the current platform.
    
    Returns:
        List of potential Python interpreter paths to try.
    """
    if sys.platform == "win32":
        return ["py", "python.exe", "python3.exe"]
    elif sys.platform == "darwin":
        return [
            "/opt/homebrew/bin/python3",
            "/usr/local/bin/python3",
            "/usr/bin/python3"
        ]
    else:  # Linux and other Unix-like systems
        return [
            "/usr/bin/python3",
            "/usr/local/bin/python3"
        ]


def is_binary_ninja_python(python_path: str) -> bool:
    """Check if a Python path appears to be Binary Ninja's embedded Python.
    
    Args:
        python_path: Path to Python interpreter to check.
        
    Returns:
        True if this appears to be Binary Ninja's embedded Python.
    """
    return "Binary Ninja" in python_path or "binaryninja" in python_path.lower()


def venv_python_path(venv_dir: str) -> str:
    """The interpreter of the virtual environment in `venv_dir` (it may not exist)."""
    if sys.platform == "win32":
        return os.path.join(venv_dir, "Scripts", "python.exe")
    return os.path.join(venv_dir, "bin", "python3")


# pip may download for a long time on a slow connection; a hung pip is still stopped eventually.
PIP_TIMEOUT_S = 900
# The packages the bridge imports (bridge/requirements.txt installs them; anyio comes with mcp).
REQUIRED_MODULES = ("mcp", "requests", "anyio")


def _requirements_importable(python: str) -> bool:
    try:
        r = subprocess.run([python, "-c", "import " + ", ".join(REQUIRED_MODULES)], capture_output=True,
                           timeout=120, creationflags=_NO_WINDOW)
        return r.returncode == 0
    except Exception:
        return False


def _pip_install(python: str, requirements_file: str, stream: bool, log) -> None:
    """pip install -r requirements_file with `python`; RuntimeError (with pip's last lines) when it fails."""
    cmd = [python, "-m", "pip", "install", "-r", requirements_file]
    log("Installing the bridge's packages (pip downloads them from PyPI): " + " ".join(cmd))
    try:
        if stream:
            r = subprocess.run(cmd, timeout=PIP_TIMEOUT_S, creationflags=_NO_WINDOW)
            tail = ""
        else:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=PIP_TIMEOUT_S, creationflags=_NO_WINDOW)
            tail = "\n".join(((r.stdout or "") + (r.stderr or "")).strip().splitlines()[-15:])
    except subprocess.TimeoutExpired:
        raise RuntimeError("pip did not finish within %d s: %s" % (PIP_TIMEOUT_S, " ".join(cmd)))
    except OSError as e:
        raise RuntimeError("pip could not be run (%s): %s" % (e, " ".join(cmd)))
    if r.returncode != 0:
        raise RuntimeError("pip failed with exit code %d: %s%s" % (r.returncode, " ".join(cmd),
                                                                  ("\n" + tail) if tail else ""))


def create_venv_with_system_python(venv_dir: str, requirements_file: str = None, stream: bool = False,
                                   log=None) -> str:
    """Create the virtual environment in `venv_dir` when it is missing (with a system Python when possible), and
    install `requirements_file` when the interpreter cannot import the bridge's packages. Every child process has its
    return code checked; a half-built environment (an interpreter without the packages) is repaired by the next run.

    Args:
        venv_dir: Directory of the virtual environment.
        requirements_file: Optional path to requirements.txt to install.
        stream: True shows pip's output on this console; False keeps its last lines for the error message.
        log: callable(str) for progress lines (default: none).

    Returns:
        Path to the Python interpreter of the virtual environment.

    Raises:
        RuntimeError: when the environment cannot be created or the packages cannot be installed.
    """
    log = log or (lambda _msg: None)
    venv_python = venv_python_path(venv_dir)

    # Check if we need to recreate the venv
    should_recreate = not os.path.exists(venv_python)
    
    # On Windows, check for Binary Ninja launcher
    if sys.platform == "win32":
        bn_launcher = os.path.join(venv_dir, "Scripts", "binaryninja.exe")
        if os.path.exists(bn_launcher):
            should_recreate = True
    
    # On macOS/Linux, check if existing venv uses Binary Ninja's Python
    if sys.platform in ("darwin", "linux") and os.path.exists(venv_python):
        try:
            result = subprocess.run(
                [venv_python, "-c", "import sys; print(sys.executable)"], 
                capture_output=True, text=True, timeout=10, creationflags=_NO_WINDOW
            )
            if result.returncode == 0 and is_binary_ninja_python(result.stdout.strip()):
                should_recreate = True
        except Exception:
            pass
    
    if should_recreate:
        os.makedirs(venv_dir, exist_ok=True)
        created = False
        log("Creating the bridge's virtual environment: " + venv_dir)

        # Try to use system Python for venv creation
        if sys.platform == "win32":
            candidates = [["py", "-3", "-m", "venv", venv_dir]]    # the Python launcher
        else:
            candidates = [[p, "-m", "venv", venv_dir] for p in get_system_python_candidates() if os.path.exists(p)]
        for cmd in candidates:
            try:
                r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=120,
                                   creationflags=_NO_WINDOW)
            except Exception:
                continue
            if r.returncode == 0 and os.path.exists(venv_python):
                created = True
                break

        # Fallback to venv.EnvBuilder if system Python methods failed (never with Binary Ninja's own interpreter,
        # which is not a standalone Python)
        if not created:
            if is_binary_ninja_python(sys.executable):
                raise RuntimeError("no system Python created %s; create it by hand (README.md, Install, step 3)"
                                   % venv_dir)
            builder = venv.EnvBuilder(with_pip=True, upgrade=False)
            builder.create(venv_dir)
            if not os.path.exists(venv_python):
                raise RuntimeError("the virtual environment %s has no interpreter %s" % (venv_dir, venv_python))

    # Install the requirements when the interpreter cannot import the bridge's packages (a new environment, or one
    # whose earlier pip run failed or was stopped).
    if requirements_file and os.path.exists(requirements_file) and not _requirements_importable(venv_python):
        _pip_install(venv_python, requirements_file, stream, log)

    return venv_python


def copy_python_env(env: dict) -> bool:
    """Copy Python-related environment variables that affect imports.
    
    Args:
        env: Dictionary to copy environment variables into.
        
    Returns:
        True if any variables were copied, False otherwise.
    """
    python_vars = [
        "PYTHONHOME",
        "PYTHONPATH", 
        "PYTHONSAFEPATH",
        "PYTHONPLATLIBDIR",
        "PYTHONPYCACHEPREFIX",
        "PYTHONNOUSERSITE",
        "PYTHONUSERBASE",
    ]
    
    copied = False
    for var in python_vars:
        value = os.environ.get(var)
        if value:
            copied = True
            env[var] = value
    
    return copied
