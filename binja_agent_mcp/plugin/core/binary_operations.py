# This file is part of binja-agent-mcp, a modified version of "Binary Ninja MCP" by fosdickio and
# CX330Blake (https://github.com/fosdickio/binary_ninja_mcp, upstream commit
# d8a2709df69ff475d6be6366c2eec733663b008b, 2025-12-16).
# Copyright (C) 2025 fosdickio, CX330Blake
# Copyright (C) 2026 Kazuma Matsumoto
# Modified by Kazuma Matsumoto between 2026-10-14 and 2026-11-18; see NOTICE.md and CHANGES-FROM-UPSTREAM.md.
# SPDX-License-Identifier: GPL-3.0-or-later
# This program comes with ABSOLUTELY NO WARRANTY; see the LICENSE file for details.
import binaryninja as bn
from typing import Optional, List, Dict, Any, Union
import weakref
import subprocess
import platform
import os
import ntpath
import posixpath
import hashlib
import sys
import threading
from contextlib import contextmanager
from .config import BinaryNinjaConfig
from . import request_context as rc
from binaryninja.enums import TypeClass, StructureVariant
from ..utils.string_utils import escape_non_ascii
import re


# --- get_xrefs_to_* stability caps ------------------------------------------
# The five get_xrefs_to_* handlers historically scanned EVERY function's HLIL
# text across the whole binary (O(functions * instructions)). That pins a core
# for minutes on large binaries (combase / chrome-class) and looks like a hang.
# Above _XREF_SCAN_FUNC_THRESHOLD functions we skip the whole-binary textual
# scan entirely and serve results from Binary Ninja's *indexed* type
# cross-reference APIs (get_code_refs_for_type / get_code_refs_for_type_field /
# get_data_refs_for_type), which are O(refs) and accept a max_items cap.
# Small binaries keep the original textual behaviour unchanged, with a hard
# match cap as a belt-and-suspenders guard.
_XREF_SCAN_FUNC_THRESHOLD = 4000   # function-count ceiling for the textual scan path
_XREF_SCAN_MAX_MATCHES = 4000      # hard cap on textual matches per result list
_XREF_NATIVE_MAX = 4000            # max_items passed to the indexed type-xref APIs


# --- per-request binary resolution ----------------------------------------------
# Selector grammar for the optional request parameter `binary` (see resolve_binary):
#   1. view:<id> | v:<id> | all digits  -> internal view id
#   2. #<n>                             -> n-th entry of the sorted /binaries listing (positional: it names
#                                          another binary after one is opened or closed; accepted, not advertised)
#   3. <64-hex sha256>                  -> view by on-disk sha256
#   4. a unique 12-63 char hex prefix   -> view by sha256 prefix
#   5. an ABSOLUTE path                 -> view by filename / original_filename
#   6. a unique basename                -> view
#   7. a unique stem (extension-less selectors only) -> view
# Paths and names compare without case on Windows only (_norm_path, _name_key).
_SHA_CHUNK = 1024 * 1024
_SHA_CACHE_MAX = 256
# Per-UNDERLYING-view memos (first-seen stat baseline, sha256 of the loaded bytes); oldest evicted first.
_VIEW_MEMO_MAX = 1024
_RE_VIEW_ID = re.compile(r"^(?:view|v):([0-9]+)$", re.IGNORECASE)
_RE_DIGITS = re.compile(r"^[0-9]+$")
_RE_ORDINAL = re.compile(r"^#([0-9]+)$")
_RE_HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")
_RE_HEXPFX = re.compile(r"^[0-9a-fA-F]{12,63}$")
_RE_DRIVE_ABS = re.compile(r"^[A-Za-z]:\\")
# Every child process is started without a console window.
_NO_WINDOW = getattr(subprocess, 'CREATE_NO_WINDOW', 0)
_WIN = sys.platform == "win32"


def _norm_path(p, win=None) -> str:
    """Normal form of a path, for comparison only. Windows: case-, slash- and \\\\?\\-insensitive. Other systems:
    posixpath.normpath alone (case is kept and a backslash is an ordinary character), so on a case-sensitive file
    system /x/a.bin never matches an open /x/A.bin."""
    win = _WIN if win is None else win
    s = str(p or "").strip()
    if not s:
        return ""
    if not win:
        return posixpath.normpath(s)
    s = s.replace("/", "\\")
    low = s.lower()
    if low.startswith("\\\\?\\unc\\"):
        s = "\\\\" + s[8:]
    elif low.startswith("\\\\?\\"):
        s = s[4:]
    try:
        s = ntpath.normpath(s)
    except Exception:
        pass
    return s.casefold()


def _is_abs_path(p, win=None) -> bool:
    """Windows: a drive-absolute, UNC/\\\\?\\ or rooted path. Other systems: a path that starts with '/'."""
    win = _WIN if win is None else win
    t = str(p or "").strip()
    if not win:
        return t.startswith("/")
    t = t.replace("/", "\\")
    if t.startswith("\\"):
        return True
    return bool(_RE_DRIVE_ABS.match(t))


def _basename(p, win=None) -> str:
    win = _WIN if win is None else win
    s = str(p or "")
    if not s:
        return ""
    return ntpath.basename(s.replace("/", "\\")) if win else posixpath.basename(s)


def _name_key(name, win=None) -> str:
    """A file name as selectors compare it: without case on Windows, exactly elsewhere."""
    win = _WIN if win is None else win
    s = str(name or "")
    return s.casefold() if win else s


def _stem(name, win=None) -> str:
    win = _WIN if win is None else win
    return (ntpath if win else posixpath).splitext(str(name or ""))[0]


# --- which paths a load may open ---------------------------------------------------
# A path reaches bn_load_binary (and the legacy /load) from the agent, and the agent may be steered by text inside an
# analyzed binary. On Windows, merely testing a UNC path (\\host\share\x) makes the SMB client connect to that host and
# authenticate with the user's credentials (NTLM). So a load path is checked as a STRING before any file-system call:
# network and device paths are refused (403 POLICY) unless Binary Ninja runs with BN_MCP_ALLOW_NETWORK_PATHS=1
# (device-namespace paths always). On Windows a local path also needs a drive letter on a drive that is not a network
# drive, and its realpath (a junction or link) is checked again.
_DRIVE_REMOTE = 4                        # GetDriveTypeW: DRIVE_REMOTE


def _drive_is_remote(path) -> bool:
    """True when the drive of a drive-absolute Windows path is a network drive (GetDriveTypeW)."""
    try:
        import ctypes
        return int(ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(path[:2] + "\\"))) == _DRIVE_REMOTE
    except Exception:
        return False


def _strip_long_prefix(t):
    low = t.lower()
    if low.startswith("\\\\?\\unc\\"):
        return "\\\\" + t[8:]
    if low.startswith("\\\\?\\") and _RE_DRIVE_ABS.match(t[4:]):
        return t[4:]
    return t


def load_path_problem(path, allow_network=False, win=None, drive_is_remote=None):
    """Why `path` must not be opened by a load, or None. String checks only (no file-system call).
    `drive_is_remote(path)` (Windows) answers the network-drive question; default: GetDriveTypeW."""
    win = _WIN if win is None else win
    s = str(path or "").strip()
    if not s:
        return "the path is empty"
    if not win:
        if not s.startswith("/"):
            return "the path is not absolute"
        if s.startswith("//") and not allow_network:
            return "a path that starts with // is refused (its meaning is implementation-defined)"
        return None
    t = s.replace("/", "\\")
    if t.startswith("\\??\\") or t.startswith("\\\\.\\") or t.startswith("\\\\?\\"):
        return "device-namespace paths (\\\\.\\, \\\\?\\, \\??\\) are never accepted"
    if t.startswith("\\\\"):
        if allow_network:
            return None
        return ("the path is on a network share; opening it would send your Windows credentials to that server "
                "(BN_MCP_ALLOW_NETWORK_PATHS=1 allows it)")
    if not _RE_DRIVE_ABS.match(t):
        return "the path is not absolute (it needs a drive letter, for example C:\\files\\a.exe)"
    remote = drive_is_remote if drive_is_remote is not None else _drive_is_remote
    if not allow_network and remote(t):
        return ("the path is on a network drive; opening it would send your Windows credentials to that server "
                "(BN_MCP_ALLOW_NETWORK_PATHS=1 allows it)")
    return None


def check_load_path(path, allow_network=False):
    """The path a load may open, or rc.ApiError POLICY (403) / BAD_ARGUMENT (400). The string is checked first; only
    then os.path.realpath runs (it opens a local path to follow junctions and links), and its result is checked
    again."""
    s = str(path or "").strip()
    why = load_path_problem(s, allow_network)
    if why is not None:
        code, status = ("BAD_ARGUMENT", 400) if ("not absolute" in why or "empty" in why) else ("POLICY", 403)
        raise rc.ApiError(code, "refused to open %s: %s" % (s, why), status)
    try:
        real = os.path.realpath(s)
    except Exception:
        real = s
    if _WIN:
        real = _strip_long_prefix(real.replace("/", "\\"))
    why = load_path_problem(real, allow_network) if real != s else None
    if why is not None:
        raise rc.ApiError("POLICY", "refused to open %s (it resolves to %s): %s" % (s, real, why), 403)
    return s


def _acquire(lock, timeout) -> bool:
    """lock.acquire with timeout=None meaning 'wait forever'."""
    if timeout is None:
        return bool(lock.acquire())
    try:
        t = float(timeout)
    except (TypeError, ValueError):
        t = 20.0
    if t < 0:
        return bool(lock.acquire())
    return bool(lock.acquire(timeout=t))


class BinaryOperations:
    def __init__(self, config: BinaryNinjaConfig, server_config=None):
        self.config = config
        # ServerConfig (lock_mode, lock_wait_s, ...). None -> defaults ('global').
        self.server_config = server_config
        # The GLOBAL selection (upstream "current view"). Request handlers read
        # `_current_view` (a class-level property below) which returns the
        # request-scoped view when a request_context scope is active.
        self._global_view: Optional[bn.BinaryView] = None
        # Registry lock: guards every registry structure below. Held only for short
        # bookkeeping; NEVER held across update_analysis, IL generation, hashing,
        # bn.load or file close.
        self._reg_lock = threading.RLock()
        # Multi-binary support. _views_by_id holds weak references; what keeps a view registered is a strong
        # reference elsewhere: _owned (views this server loaded), _pinned (views open in a Binary Ninja UI tab,
        # maintained by sync_ui_views / release_file from the UI glue) or the caller's own reference. Binary Ninja
        # creates a new Python wrapper for each event callback, so a wrapper nobody keeps dies when its callback
        # returns; a pinned view keeps its id for as long as its tab is open.
        self._views_by_id: dict[str, weakref.ReferenceType] = {}
        self._next_view_id: int = 1
        self._id_by_filename: dict[str, str] = {}
        self._owned: dict = {}          # view_id -> strong ref (views this server loaded/created)
        self._pinned: dict = {}         # view_id -> strong ref (views open in a Binary Ninja UI tab)
        self._closing: set = set()      # view_ids being closed (requests get 410 GONE)
        self._view_locks: dict = {}     # view_id -> RLock (lock_mode 'per-view')
        self._global_lock = threading.RLock()   # the ONE lock in lock_mode 'global'
        self._sha_cache: dict = {}      # (path, size, mtime_ns) -> sha256 hex
        self._stat_at_reg: dict = {}    # view_id -> first-seen (path, size, mtime_ns) of the view holding that id
        # Per-FILE-SESSION (else per-view) memo {'base': first-seen stat, 'content': sha256 of the
        # loaded bytes}, see _memo_key. Handle-hashed objects (Binary Ninja: hash == core handle
        # address) are keyed by (hash, session id) so a new Python wrapper finds its memo;
        # identity-hashed objects live in a WeakKeyDictionary (the entry dies with the object, so a
        # reused id() never inherits it).
        self._memo_by_handle: dict = {}
        self._memo_by_obj = weakref.WeakKeyDictionary()
        # patch_bytes writes this session. The DURABLE record is the file-session memo's 'raw' list (it
        # outlives the view id: a pruned or unregistered id of a still-open view re-registers under a NEW
        # id); this per-id map is a mirror of the same record dicts (for a reader holding an id that was
        # since removed, and for a view no memo can be kept for). Both are dropped ONLY by close_owned_view;
        # readers use _raw_records (deduplicated by identity).
        self._raw_patches: dict = {}    # view_id -> [{va, len, orig_hex, new_hex}]

    # Request-scoped view: the override from request_context.scope() when active,
    # else the global selection. Writing it always writes the GLOBAL selection.
    def _cv_get(self):
        o = rc.override_view()
        return self._global_view if o is rc.UNSET else o

    def _cv_set(self, bv):
        self._global_view = bv

    _current_view = property(_cv_get, _cv_set)

    @property
    def current_view(self) -> Optional[bn.BinaryView]:
        return self._current_view

    @current_view.setter
    def current_view(self, bv: Optional[bn.BinaryView]):
        # Writes the GLOBAL selection. Register BEFORE selecting: registration prunes dead
        # views and would otherwise clear a selection that is not registered yet. The
        # selection is the REGISTERED object of bv's id (bv itself, an equal wrapper, or the
        # analysis view of bv's file session when bv is its Raw view), so a prune never
        # mistakes it for an unregistered view.
        if bv:
            bn.log_debug(f"Set current binary view: {bv.file.filename}")
            sel = bv
            try:
                vid = self._register_view(bv)
                with self._reg_lock:
                    obj = self._obj(vid) if vid else None
                if obj is not None:
                    sel = obj
            except Exception:
                pass
            self._global_view = sel
        else:
            self._global_view = bv
            bn.log_debug("Cleared current binary view")

    @property
    def lock_mode(self) -> str:
        m = str(getattr(self.server_config, "lock_mode", "global") or "global").strip().lower()
        return m if m in ("global", "per-view") else "global"

    @property
    def lock_wait_s(self) -> float:
        try:
            v = float(getattr(self.server_config, "lock_wait_s", 20.0))
        except (TypeError, ValueError):
            v = 20.0
        return v if v > 0 else 20.0

    def find_owned_view(self, filepath):
        """The server-owned view of `filepath` whose loaded bytes still equal the file (view_sha256 source 'file'),
        else None. Comparison by the normalized path."""
        want = _norm_path(filepath)
        if not want:
            return None
        with self._reg_lock:
            self._prune_views()
            cands = [(vid, bv) for vid, bv in self._owned.items()
                     if vid not in self._closing
                     and bv is not None and want in (_norm_path(self._filename_of(bv)), _norm_path(self._original_of(bv)))]
        for _vid, bv in sorted(cands, key=lambda t: int(t[0]) if str(t[0]).isdigit() else 0, reverse=True):
            try:
                _h, src = self.view_sha256(bv)
            except Exception:
                src = None
            if src == "file":
                return bv
        return None

    @property
    def allow_network_paths(self) -> bool:
        return bool(getattr(self.config, "allow_network_paths", False))

    @property
    def max_owned_views(self) -> int:
        try:
            n = int(getattr(self.config, "max_owned_views", 8))
        except (TypeError, ValueError):
            n = 8
        return n if n >= 1 else 8

    def _check_owned_room(self, filepath) -> None:
        """POLICY (403) when the server already holds max_owned_views views it loaded: a looping agent cannot keep
        loading files until Binary Ninja runs out of memory. The answer names the views to close."""
        with self._reg_lock:
            self._prune_views()
            owned = [(vid, self._filename_of(bv) or "") for vid, bv in self._owned.items() if vid not in self._closing]
        cap = self.max_owned_views
        if len(owned) >= cap:
            raise rc.ApiError(
                "POLICY",
                "refused to open %s: the server already holds %d binaries it loaded (BN_MCP_MAX_OWNED=%d); close one "
                "first (bn_close_binary)" % (filepath, len(owned), cap),
                403, {"owned": [{"selector": "view:" + vid, "filename": fn} for vid, fn in owned]})

    def load_binary_async(self, filepath: str) -> dict:
        """POST /x/loadBinary: bn.load(filepath, update_analysis=False), then a NON-blocking bv.update_analysis().
        Idempotent: an owned view of the same path whose loaded bytes equal the file is returned instead of a
        second view. Fills an EMPTY global selection only. -> {view_id, binary_id, analysis_state, reused}.
        The path is checked before any file-system call (check_load_path: no network or device path)."""
        fp = str(filepath or "").strip()
        if not fp:
            raise rc.ApiError("BAD_ARGUMENT", "filepath is required", 400)
        if not _is_abs_path(fp):
            raise rc.ApiError("BAD_ARGUMENT", "filepath must be an ABSOLUTE path", 400)
        fp = check_load_path(fp, self.allow_network_paths)
        if not os.path.isfile(fp):
            raise rc.NotFoundError("file", fp)
        bv = self.find_owned_view(fp)
        reused = bv is not None
        if bv is None:
            self._check_owned_room(fp)
            bv = bn.load(fp, update_analysis=False)
            if bv is None:
                raise rc.ApiError("NOT_FOUND", "Binary Ninja could not open %s" % fp, 404)
            try:
                self.mark_owned(bv)
            except Exception:
                pass
            try:
                bv.update_analysis()
            except Exception as e:
                bn.log_warn(f"load_binary_async: update_analysis failed: {e}")
        if self._global_view is None:
            try:
                with self._reg_lock:
                    vid0 = self._id_of(bv)
                    obj = self._obj(vid0) if vid0 else None
                self._global_view = obj if obj is not None else bv
            except Exception:
                self._global_view = bv
        with self._reg_lock:
            vid = self._id_of(bv) or ""
        an = self.analysis_summary(bv)
        return {"view_id": vid, "binary_id": self.binary_id(bv), "analysis_state": an.get("state"),
                "analysis_state_code": an.get("state_code"), "reused": reused, "filename": self._filename_of(bv)}

    def load_binary(self, filepath: str) -> bn.BinaryView:
        """Load a binary file using the appropriate method based on the Binary Ninja API version.

        bn.load is tried first (open_view / get_view_of_file are absent on 6.0);
        the loaded view becomes the GLOBAL selection (legacy /load selects it), is
        registered, and is OWNED by the server (strong ref; closable via
        close_owned_view). Idempotent: when the server already owns a view of
        the same normalized path whose loaded bytes still equal the file, that view is
        selected and returned instead of loading a second one (a second view would
        make every path / basename selector of the file answer 409 AMBIGUOUS).
        A relative path is made absolute against Binary Ninja's working directory (upstream accepted it); the
        result is checked like a /x/loadBinary path (check_load_path) before any file-system call.
        """
        fp = str(filepath or "").strip()
        if fp and not _is_abs_path(fp):
            fp = os.path.abspath(fp)
        filepath = check_load_path(fp, self.allow_network_paths)
        try:
            existing = self.find_owned_view(filepath)
        except Exception:
            existing = None
        if existing is not None:
            self.current_view = existing
            return existing
        self._check_owned_room(filepath)
        try:
            loaded = None
            first_err = None
            if hasattr(bn, "load"):
                try:
                    bn.log_debug("Using bn.load method")
                    loaded = bn.load(filepath, update_analysis=True)
                except Exception as e:
                    first_err = e
                    loaded = None
            if loaded is None:
                if hasattr(bn, "open_view"):
                    bn.log_debug("Using bn.open_view method")
                    loaded = bn.open_view(filepath)
                elif hasattr(bn, "BinaryViewType") and hasattr(
                    bn.BinaryViewType, "get_view_of_file"
                ):
                    bn.log_debug("Using BinaryViewType.get_view_of_file method")
                    file_metadata = bn.FileMetadata()
                    try:
                        if hasattr(bn.BinaryViewType, "get_default_options"):
                            options = bn.BinaryViewType.get_default_options()
                            loaded = bn.BinaryViewType.get_view_of_file(
                                filepath, file_metadata, options
                            )
                        else:
                            loaded = bn.BinaryViewType.get_view_of_file(
                                filepath, file_metadata
                            )
                    except TypeError:
                        loaded = bn.BinaryViewType.get_view_of_file(filepath)
                elif first_err is not None and not (
                    hasattr(bn, "BinaryViewType")
                    and hasattr(bn.BinaryViewType, "get_view_of_file_with_options")
                ):
                    raise first_err
                else:
                    bn.log_debug("Using legacy method")
                    file_metadata = bn.FileMetadata()
                    binary_view_type = bn.BinaryViewType.get_view_of_file_with_options(
                        filepath, file_metadata
                    )
                    if binary_view_type:
                        loaded = binary_view_type.open()
                    else:
                        raise Exception("No view type available for this file")
            if loaded is None:
                if first_err is not None:
                    raise first_err
                raise Exception(f"Unable to load binary: {filepath}")

            # Register/own BEFORE selecting (registration prunes and would clear an
            # unregistered selection).
            try:
                self.mark_owned(loaded)
            except Exception:
                pass
            self._global_view = loaded
            return loaded
        except Exception as e:
            bn.log_error(f"Failed to load binary: {e}")
            raise

    # ---------------- Multi-binary helpers ----------------
    @staticmethod
    def _deref(w):
        try:
            return w() if w is not None else None
        except Exception:
            return None

    @staticmethod
    def _same(a, b) -> bool:
        if a is b:
            return True
        if a is None or b is None:
            return False
        try:
            return bool(a == b)
        except Exception:
            return False

    def _same_session(self, a, b) -> bool:
        """True when two views belong to ONE file session (one FileMetadata: e.g. the Raw parent and
        the PE view of one open file). Two tabs or loads of the same path are two sessions."""
        if a is None or b is None:
            return False
        try:
            fa = getattr(a, "file", None)
            fb = getattr(b, "file", None)
        except Exception:
            return False
        if fa is None or fb is None:
            return False
        return self._same(fa, fb)

    @staticmethod
    def _is_raw_view(bv) -> bool:
        try:
            return str(getattr(bv, "view_type", "") or "") == "Raw"
        except Exception:
            return False

    @staticmethod
    def _filename_of(bv) -> Optional[str]:
        try:
            fn = getattr(bv.file, "filename", None) if getattr(bv, "file", None) else None
            return str(fn) if fn else None
        except Exception:
            return None

    @staticmethod
    def _original_of(bv) -> Optional[str]:
        try:
            fn = getattr(bv.file, "original_filename", None) if getattr(bv, "file", None) else None
            return str(fn) if fn else None
        except Exception:
            return None

    def _is_db(self, bv) -> bool:
        """True for a view opened from a .bndb database (its bytes come from the database, not the file)."""
        fn = self._filename_of(bv)
        return bool(fn) and fn.lower().endswith(".bndb")

    @staticmethod
    def _backed_by_database(bv) -> bool:
        """FileMetadata.has_database (Binary Ninja), False when unknown."""
        try:
            return getattr(getattr(bv, "file", None), "has_database", False) is True
        except Exception:
            return False

    def _image_path(self, bv) -> Optional[str]:
        """The on-disk image backing a view: original_filename for a .bndb, else filename."""
        fn = self._filename_of(bv)
        if fn and fn.lower().endswith(".bndb"):
            return self._original_of(bv)
        return fn or self._original_of(bv)

    def _stat_of(self, bv):
        p = self._image_path(bv)
        if not p:
            return None
        try:
            st = os.stat(p)
            return (p, int(st.st_size), int(st.st_mtime_ns))
        except Exception:
            return None

    @staticmethod
    def _memo_key(bv):
        """Hashable key of the memo owner of `bv`, or None (then _memo_of uses the WeakKeyDictionary).

        Binary Ninja's FileMetadata and BinaryView hash by their core handle address, so every
        Python wrapper of one object agrees:
        - ('s', hash(file), session_id): the FILE SESSION (one FileMetadata: every view of it,
          e.g. the Raw parent and the PE view, holds that one file's bytes), when the
          FileMetadata type is handle-hashed and has an int session_id;
        - ('v', hash(view), session_id | None): the underlying VIEW, when only the view type is
          handle-hashed;
        - None: identity-hashed or unhashable objects. Never raises.
        """
        if bv is None:
            return None

        def _handle_hashed(o):
            try:
                hf = type(o).__hash__
                return hf is not None and hf is not object.__hash__
            except Exception:
                return False

        try:
            f = getattr(bv, "file", None)
        except Exception:
            f = None
        sid = None
        try:
            s = getattr(f, "session_id", None) if f is not None else None
            if isinstance(s, int) and not isinstance(s, bool):
                sid = int(s)
        except Exception:
            sid = None
        try:
            if f is not None and sid is not None and _handle_hashed(f):
                return ("s", hash(f), sid)
            if _handle_hashed(bv):
                return ("v", hash(bv), sid)
        except Exception:
            return None
        return None

    # Earlier name of _memo_key (kept: callers pass its result to _memo_of / _forget_memo).
    _handle_key = _memo_key

    @staticmethod
    def _memo_owners(bv):
        """WeakKeyDictionary owners of an identity-hashed `bv`: its FileMetadata (the file session),
        then the view itself."""
        out = []
        try:
            f = getattr(bv, "file", None)
        except Exception:
            f = None
        if f is not None:
            out.append(f)
        if bv is not None:
            out.append(bv)
        return out

    def _memo_of(self, bv, mk):
        """The memo dict of the file session (else the view) behind `bv`, created on first use
        (`mk` = _memo_key(bv)); None when nothing can own one. Call under _reg_lock."""
        if mk is not None:
            m = self._memo_by_handle.get(mk)
            if m is None:
                if len(self._memo_by_handle) >= _VIEW_MEMO_MAX:
                    # Evict the oldest memo that holds NO raw-patch record: a 'raw' list is the fail-closed
                    # record of patch_bytes writes (raw_patches / modified) and is dropped only by
                    # close_owned_view. When every memo holds one, none is evicted (the cap is exceeded).
                    victim = None
                    try:
                        for k, v in self._memo_by_handle.items():
                            if not (isinstance(v, dict) and v.get("raw")):
                                victim = k
                                break
                    except Exception:
                        victim = None
                    if victim is not None:
                        self._memo_by_handle.pop(victim, None)
                m = {}
                self._memo_by_handle[mk] = m
            return m
        for o in self._memo_owners(bv):
            try:
                m = self._memo_by_obj.get(o)
                if m is None:
                    m = {}
                    self._memo_by_obj[o] = m
                return m
            except Exception:
                continue
        return None

    def _first_seen_stat(self, bv):
        """Stat baseline of the file session (else the underlying view) behind `bv`, taken when the
        server FIRST registered a view of it and never refreshed: a later registration (a re-created
        Python wrapper after its id was pruned, another view of the same session, a view reclaiming
        an id) keeps it, and a different session of the same path gets its own (it can neither reset
        nor inherit another session's baseline). Call under _reg_lock."""
        m = self._memo_of(bv, self._memo_key(bv))
        if m is None:
            return self._stat_of(bv)
        if "base" not in m:
            m["base"] = self._stat_of(bv)
        return m["base"]

    def _memo_peek(self, bv, mk):
        """The existing memo of `bv` (`mk` = _memo_key(bv)) WITHOUT creating one: the same owner lookup as
        _memo_of. None when there is none. Never raises. Call under _reg_lock."""
        if bv is None:
            return None
        if mk is not None:
            return self._memo_by_handle.get(mk)
        for o in self._memo_owners(bv):
            try:
                return self._memo_by_obj.get(o)
            except Exception:
                continue
        return None

    def _raw_records(self, vid, bv=None) -> list:
        """The patch_bytes records of view id `vid` (and/or of view `bv`): the file-session memo's 'raw' list
        of `bv` and of the live object of `vid` (it survives id churn), plus the per-id mirror of `vid` (it
        survives the id's removal), deduplicated by identity (each list keeps its recording order). The ORIGINAL
        dicts (callers copy). Never raises. Call under _reg_lock."""
        out, seen = [], set()

        def _add(lst):
            for x in list(lst or []):
                if id(x) not in seen:
                    seen.add(id(x))
                    out.append(x)

        objs = []
        if bv is not None:
            objs.append(bv)
        o = self._obj(vid) if vid else None
        if o is not None and not any(x is o for x in objs):
            objs.append(o)
        for ob in objs:
            try:
                m = self._memo_peek(ob, self._memo_key(ob))
            except Exception:
                m = None
            if isinstance(m, dict):
                _add(m.get("raw"))
        if vid:
            _add(self._raw_patches.get(vid))
        return out

    def _forget_memo(self, bv, mk) -> None:
        """Drop the memo of a view that is CLOSED for good (close_owned_view). Call under _reg_lock."""
        if mk is not None:
            self._memo_by_handle.pop(mk, None)
            return
        for o in self._memo_owners(bv):
            try:
                self._memo_by_obj.pop(o, None)
            except Exception:
                pass

    def _loaded_content_sha(self, bv):
        """sha256 of the FILE bytes `bv` was loaded from -> (hex | None, supported).

        Hashes the view's 'Raw' BinaryView (FileMetadata.raw: the whole file as Binary Ninja holds
        it; for a .bndb, the file data stored in the database) in 1 MB reads, outside every
        registry lock, ONCE per file session (memoized, so later raw patch_bytes writes do not
        change it; a write made BEFORE the first hash makes it differ from the file, which only
        withholds 'file'). supported=False: this API exposes no FileMetadata.raw (callers fall
        back to the first-seen stat baseline, except for a .bndb, which then never reports
        'file'). (None, True): the bytes could not be read completely, which never vouches for
        anything (and is not memoized: the next request re-reads, so a transient failure does
        not withhold 'file' for longer than it lasts).
        """
        try:
            f = getattr(bv, "file", None)
        except Exception:
            return None, True
        if f is None:
            return None, False
        try:
            supported = hasattr(type(f), "raw") or ("raw" in getattr(f, "__dict__", {}))
        except Exception:
            supported = False
        if not supported:
            return None, False
        mk = self._memo_key(bv)
        with self._reg_lock:
            m = self._memo_of(bv, mk)
            h = m.get("content") if m is not None else None
        if h:
            return h, True
        try:
            raw = f.raw
            if raw is None:
                return None, True
            try:
                n = int(raw.length)
            except Exception:
                n = int(len(raw))
            start = int(getattr(raw, "start", 0) or 0)
            if n < 0:
                return None, True
            d = hashlib.sha256()
            off = 0
            while off < n:
                want = min(_SHA_CHUNK, n - off)
                chunk = raw.read(start + off, want)
                if not chunk or len(chunk) != want:
                    return None, True
                d.update(chunk)
                off += want
            h = d.hexdigest()
        except Exception:
            return None, True
        with self._reg_lock:
            m = self._memo_of(bv, mk)
            if m is not None:
                h = m.setdefault("content", h)
        return h, True

    def _obj(self, vid):
        """Live object for a view id (weakref, else the owned or pinned strong ref). Call under _reg_lock."""
        vb = self._deref(self._views_by_id.get(vid))
        if vb is None:
            vb = self._owned.get(vid)
        if vb is None:
            vb = self._pinned.get(vid)
        return vb

    def _id_of(self, bv) -> Optional[str]:
        """View id of a BinaryView, or None. Call under _reg_lock."""
        if bv is None:
            return None
        for vid in list(self._views_by_id.keys()):
            if self._same(self._obj(vid), bv):
                return vid
        return None

    def _prune_views(self) -> None:
        """Remove entries for BinaryViews that no longer exist and rebuild filename map.

        Owned (server-loaded) and pinned (open in a UI tab) ids are kept alive by their strong reference.
        """
        with self._reg_lock:
            alive: dict[str, weakref.ReferenceType] = {}
            new_fn_map: dict[str, str] = {}
            alive_objs: list[object] = []
            for vid, w in list(self._views_by_id.items()):
                vb = self._deref(w)
                if vb is None:
                    vb = self._owned.get(vid)
                    if vb is None:
                        vb = self._pinned.get(vid)
                    if vb is not None:
                        try:
                            w = weakref.ref(vb)
                        except Exception:
                            pass
                if vb is None:
                    continue
                alive[vid] = w
                alive_objs.append(vb)
                fn = self._filename_of(vb)
                if fn and fn not in new_fn_map:
                    new_fn_map[fn] = vid
            dropped = [vid for vid in self._views_by_id.keys() if vid not in alive]
            self._views_by_id = alive
            self._id_by_filename = new_fn_map
            for vid in dropped:
                # _raw_patches is NOT dropped here: an id is dropped when its registered Python wrapper dies,
                # while the view itself may still be open (it re-registers under a new id). Ids are never
                # reused, so the mirror cannot leak into another view; close_owned_view drops it.
                self._stat_at_reg.pop(vid, None)
                self._view_locks.pop(vid, None)
                self._closing.discard(vid)
            # If the global selection no longer exists among alive views, clear it
            # (compared like registration: any wrapper of a registered view counts)
            try:
                gv = self._global_view
                if gv is not None and not any(self._same(obj, gv) for obj in alive_objs):
                    self._global_view = None
            except Exception:
                self._global_view = None

    def _register_view(self, bv: bn.BinaryView) -> str:
        """Add a view to the managed list if not present, return its id.

        One id per FILE SESSION (one FileMetadata):
        * the same underlying view (any Python wrapper of it) -> its id;
        * another view of the SAME session (e.g. the Raw parent of a PE view) -> that session's id.
          The id is re-pointed only to upgrade a Raw view to an analysis view (the global selection
          follows), never the reverse;
        * any other view, including a second tab or load of the SAME path (it may hold different
          bytes) -> its OWN new id. An existing id is never re-pointed to another session, so a
          path/basename/stem selector answers 409 AMBIGUOUS instead of silently answering from
          whichever view registered last, and the legacy global selection is never dropped by it.
        """
        with self._reg_lock:
            self._prune_views()
            # Reuse existing id if the exact object (or the same underlying view) is already tracked
            for vid in list(self._views_by_id.keys()):
                if self._same(self._obj(vid), bv):
                    return vid
            # Another view of an already-registered file session keeps that session's ONE id
            for vid in list(self._views_by_id.keys()):
                prev = self._obj(vid)
                if prev is None or not self._same_session(prev, bv):
                    continue
                if vid not in self._owned and self._is_raw_view(prev) and not self._is_raw_view(bv):
                    # Always store weak references so closed views can be pruned
                    self._views_by_id[vid] = weakref.ref(bv)
                    # Same session, same loaded bytes: a not-yet-seen analysis view inherits the
                    # session's (earlier) baseline instead of a fresh stat of the current file.
                    m = self._memo_of(bv, self._handle_key(bv))
                    if m is not None and "base" not in m and vid in self._stat_at_reg:
                        m["base"] = self._stat_at_reg[vid]
                    self._stat_at_reg[vid] = self._first_seen_stat(bv)
                    if self._global_view is not None and self._same(self._global_view, prev):
                        self._global_view = bv
                return vid
            # Assign a new id
            fn = self._filename_of(bv)
            vid = str(self._next_view_id)
            self._next_view_id += 1
            self._views_by_id[vid] = weakref.ref(bv)
            if fn and fn not in self._id_by_filename:
                self._id_by_filename[fn] = vid
            self._stat_at_reg[vid] = self._first_seen_stat(bv)
            return vid

    def register_view(self, bv: bn.BinaryView) -> str:
        """Public wrapper to register a BinaryView and return its id."""
        return self._register_view(bv)

    # ---------------- views open in the Binary Ninja UI ----------------
    def _forget_ui_id(self, vid) -> None:
        """Unregister a (non-owned) id whose view is no longer open in the UI, and clear the global selection when it
        belongs to that view's file session. Call under _reg_lock."""
        obj = self._pinned.pop(vid, None)
        if obj is None:
            obj = self._obj(vid)
        if vid in self._owned:
            return
        self._views_by_id.pop(vid, None)
        self._stat_at_reg.pop(vid, None)
        self._view_locks.pop(vid, None)
        self._closing.discard(vid)
        gv = self._global_view
        if gv is not None and obj is not None and (self._same(gv, obj) or self._same_session(gv, obj)):
            self._global_view = None

    def sync_ui_views(self, views, active=None, complete=True) -> dict:
        """Make the registry match the views open in Binary Ninja's UI (called by the UI glue on the main thread).

        Every view in `views` is registered (an already registered view keeps its id) and PINNED: the registry
        holds a strong reference while the view is open, because Binary Ninja's Python wrappers are created per
        call and a wrapper nobody keeps dies at once. With complete=True `views` is the whole list of open UI
        views: a pinned id whose view is no longer in it was closed in the UI and is unregistered (owned views are
        never touched). `active` (the view of the active UI tab) becomes the global selection when there is none.
        -> {'pinned': [ids], 'removed': [ids]}."""
        views = [v for v in list(views or []) if v is not None]
        with self._reg_lock:
            keep = {}
            for bv in views:
                vid = self._register_view(bv)
                if vid:
                    keep[vid] = bv
            for vid in list(keep):
                obj = self._deref(self._views_by_id.get(vid))
                # pin the object the id points to (for a Raw view and its analysis view, the analysis view)
                self._pinned[vid] = obj if obj is not None else keep[vid]
            removed = []
            if complete:
                for vid in list(self._pinned):
                    if vid not in keep and vid not in self._owned:
                        removed.append(vid)
                for vid in removed:
                    self._forget_ui_id(vid)
            if active is not None and self._global_view is None:
                avid = self._id_of(active)
                if avid:
                    self._global_view = self._obj(avid)
            self._prune_views()
            return {"pinned": sorted(keep, key=lambda v: int(v) if v.isdigit() else 0), "removed": removed}

    def release_file(self, file_metadata=None, filename=None) -> int:
        """A file was closed in the UI: unregister the non-owned views of that file session (compared by the
        FileMetadata when given; by the file name when no view matches it) and clear the global selection if it was
        one of them. A still-open second session of the same file is registered again by the next sync.
        -> number of ids removed."""
        if file_metadata is None and not filename:
            return 0
        with self._reg_lock:
            by_md, by_name = [], []
            for vid in list(self._views_by_id.keys()):
                if vid in self._owned:
                    continue
                obj = self._obj(vid)
                if obj is None:
                    continue
                try:
                    f = getattr(obj, "file", None)
                except Exception:
                    f = None
                if file_metadata is not None and f is not None and self._same(f, file_metadata):
                    by_md.append(vid)
                elif filename and self._filename_of(obj) == filename:
                    by_name.append(vid)
            gone = by_md or by_name
            for vid in gone:
                self._forget_ui_id(vid)
            self._prune_views()
            return len(gone)

    def available_binaries(self) -> list:
        """[{view_id, selector, filename, basename}] of the open binaries (the `available` list of a NOT_FOUND)."""
        return self._available(self._snapshot())

    def list_open_binaries(self) -> list[dict[str, str]]:
        """Return a list of managed/open binaries with ids.

        Note: Tracks binaries opened via this plugin or explicitly registered as current_view.
        Items carry the additive key 'owned' (server-loaded).
        """
        items: list[dict[str, str]] = []
        with self._reg_lock:
            # Cleanup first
            self._prune_views()
            # Do NOT auto-register current_view here: views open in the UI are registered by sync_ui_views (the
            # UI glue), so a closed view is never re-introduced through a stale strong reference.
            # Every id is listed: an id is ONE file session (_register_view), so two ids that share a
            # filename are two sessions of that file (they may hold different bytes) and neither may be
            # hidden behind the other.
            entries: list[tuple] = []  # (id, filename, active, owned)
            gv = self._global_view
            for vid in list(self._views_by_id.keys()):
                vb = self._obj(vid)
                if vb is None:
                    continue
                try:
                    fn = vb.file.filename
                except Exception:
                    fn = "(unknown)"
                entries.append((vid, fn, bool(gv is not None and self._same(vb, gv)), vid in self._owned))
        # Sort by filename for stable ordering
        entries.sort(key=lambda t: ((t[1] or ""), int(t[0]) if str(t[0]).isdigit() else 0))
        for cid, fn, active, owned in entries:
            items.append({"id": cid, "filename": fn, "active": active, "owned": owned})
        return items

    def select_view(self, ident: str) -> dict[str, str] | None:
        """Select active BinaryView by id or filename/basename.

        Returns selection info on success, None on failure.
        """
        s = (ident or "").strip()
        if not s:
            return None
        with self._reg_lock:
            self._prune_views()
            # Try id
            vb = None
            if s in self._views_by_id:
                vb = self._obj(s)
            # If user passed a 1-based ordinal (from /binaries), map it to its entry
            if vb is None and s.isdigit():
                try:
                    idx = int(s)
                    if idx >= 1:
                        lst = self.list_open_binaries()  # sorted order
                        if 1 <= idx <= len(lst):
                            map_id = str(lst[idx - 1].get("id") or "")
                            if map_id:
                                vb = self._obj(map_id)
                except Exception:
                    vb = None
            # Try direct filename mapping (several sessions of that file: _prefer_session)
            if vb is None:
                try:
                    # Exact filename
                    same_fn = self._ids_with_filename(s)
                    if same_fn:
                        vb = self._obj(self._prefer_session(same_fn))
                except Exception:
                    vb = None
            if vb is None:
                # Try match by full filename or basename (first match; several sessions of THAT
                # file: _prefer_session)
                for vid in list(self._views_by_id.keys()):
                    v = self._obj(vid)
                    if v is None:
                        continue
                    try:
                        fn = v.file.filename
                    except Exception:
                        fn = None
                    if not fn:
                        continue
                    if s == fn or s == os.path.basename(fn):
                        vb = v
                        try:
                            same_fn = self._ids_with_filename(fn)
                            if len(same_fn) > 1:
                                vb = self._obj(self._prefer_session(same_fn)) or v
                        except Exception:
                            vb = v
                        break
            if vb is None:
                return None
            self.current_view = vb
            vid = self._id_of(vb)
            return {"id": vid or "", "filename": getattr(vb.file, 'filename', '(unknown)')}

    def _ids_with_filename(self, fn) -> list:
        """Ids of the live views whose filename is exactly `fn`, in registration order.
        Call under _reg_lock."""
        out = []
        if not fn:
            return out
        for vid in list(self._views_by_id.keys()):
            v = self._obj(vid)
            if v is not None and self._filename_of(v) == fn:
                out.append(vid)
        return out

    def _prefer_session(self, vids):
        """LEGACY (selector-less) pick among ids that share ONE filename, i.e. several sessions of one
        file: the session whose first-seen on-disk baseline still matches the file (it most likely holds
        the file's current bytes), then the newest id. An explicit `binary` selector never guesses; it
        answers 409 AMBIGUOUS (resolve_binary). Call under _reg_lock (stat only, never hashing)."""
        if len(vids) == 1:
            return vids[0]

        def _rank(v):
            o = self._obj(v)
            reg = self._stat_at_reg.get(v)
            cur = self._stat_of(o) if o is not None else None
            fresh = reg is not None and cur is not None and tuple(reg) == tuple(cur)
            return (1 if fresh else 0, int(v) if str(v).isdigit() else 0)

        return max(vids, key=_rank)

    # ---------------- Per-request resolution, locks, ownership ----------------
    def global_view(self):
        """The GLOBAL selection (ignores any request scope)."""
        return self._global_view

    def open_view_count(self) -> int:
        with self._reg_lock:
            self._prune_views()
            return len(self._views_by_id)

    def _disk_sha256(self, bv):
        """sha256 of the ON-DISK image backing `bv` -> (hex | None, (path, size, mtime_ns) | None).

        Hashing runs outside every lock in 1 MB chunks and is cached by (path, size, mtime_ns);
        a file that changes while it is hashed yields (None, None).
        """
        if bv is None:
            return None, None
        path = self._image_path(bv)
        if not path:
            return None, None
        try:
            st = os.stat(path)
        except Exception:
            return None, None
        key = (path, int(st.st_size), int(st.st_mtime_ns))
        with self._reg_lock:
            h = self._sha_cache.get(key)
        if h is None:
            try:
                d = hashlib.sha256()
                with open(path, "rb") as f:
                    while True:
                        chunk = f.read(_SHA_CHUNK)
                        if not chunk:
                            break
                        d.update(chunk)
                h = d.hexdigest()
                st2 = os.stat(path)
            except Exception:
                return None, None
            if (int(st2.st_size), int(st2.st_mtime_ns)) != (key[1], key[2]):
                # The file changed while it was being hashed: the digest vouches for nothing.
                return None, None
            with self._reg_lock:
                if len(self._sha_cache) >= _SHA_CACHE_MAX:
                    try:
                        self._sha_cache.pop(next(iter(self._sha_cache)))
                    except Exception:
                        self._sha_cache.clear()
                self._sha_cache[key] = h
        return h, key

    def view_sha256(self, bv):
        """sha256 of the ON-DISK image backing `bv` -> (hex | None, source).

        source:
        - 'file': the bytes the view was LOADED from equal that file. When the API exposes
          the view's Raw view (Binary Ninja: FileMetadata.raw), this compares the sha256 of
          those loaded bytes (hashed once per file session, _loaded_content_sha) with the
          on-disk sha256. Otherwise it falls back to the first-seen stat baseline of the
          file session (_first_seen_stat): the file's (path, size, mtime_ns) must equal the
          stat taken when the server FIRST registered a view of that session. A .bndb view
          never takes the stat fallback: it is analysed from its database, so a stat of
          original_filename says nothing about the bytes it holds.
        - 'file-changed-since-load': anything else (different content, a size/mtime change,
          no baseline, an unregistered view in the stat fallback, a .bndb whose loaded bytes
          cannot be compared, or loaded bytes that could not be read).
        - 'unavailable': no on-disk file hash.
        """
        h, key = self._disk_sha256(bv)
        if h is None or key is None:
            return None, "unavailable"
        content, supported = self._loaded_content_sha(bv)
        if supported:
            return h, ("file" if (content is not None and content == h) else "file-changed-since-load")
        if self._is_db(bv):
            return h, "file-changed-since-load"
        with self._reg_lock:
            vid = self._id_of(bv)
            reg = self._stat_at_reg.get(vid) if vid else None
        source = "file" if (reg is not None and tuple(reg) == key) else "file-changed-since-load"
        return h, source

    def binary_id(self, bv) -> str:
        """Stable id: '<sha256>' of the file on disk, or 'view:<id>' when no hash is available."""
        h, _key = self._disk_sha256(bv)
        if h:
            return h
        with self._reg_lock:
            vid = self._id_of(bv)
        return ("view:%s" % vid) if vid else ""

    def analysis_summary(self, bv) -> dict:
        """{'state': AnalysisState NAME, 'state_code': int, 'progress': str}, or {'state': 'unknown'}."""
        try:
            x = bv.analysis_state
            try:
                from binaryninja.enums import AnalysisState as _AnalysisState
                st = _AnalysisState(int(x))
                name, code = st.name, int(st)
            except Exception:
                name = getattr(x, "name", None) or str(x)
                code = int(x)
            try:
                prog = str(bv.analysis_progress)
            except Exception:
                prog = ""
            return {"state": name, "state_code": code, "progress": prog}
        except Exception:
            return {"state": "unknown"}

    def describe_view(self, bv, resolved_by="explicit"):
        """The `_binary` echo for a view (never raises; None for no view)."""
        if bv is None:
            return None
        with self._reg_lock:
            vid = self._id_of(bv)
            owned = bool(vid) and vid in self._owned
            nraw = len(self._raw_records(vid, bv))
        fn = self._filename_of(bv) or ""
        orig = self._original_of(bv) or ""
        img = self._image_path(bv) or fn
        sha, src = self.view_sha256(bv)
        if sha:
            bid = sha
        else:
            bid = ("view:%s" % vid) if vid else ""
        an = self.analysis_summary(bv)
        return {
            "view_id": vid or "",
            "binary_id": bid,
            "sha256": sha,
            "sha256_source": src,
            "filename": fn,
            "original_filename": orig,
            "basename": _basename(img),
            "owned": owned,
            "modified": nraw > 0,
            "resolved_by": resolved_by,
            "analysis_state": an.get("state"),
            "analysis_state_code": an.get("state_code"),
        }

    def _snapshot(self) -> list:
        with self._reg_lock:
            self._prune_views()
            out = []
            for vid in list(self._views_by_id.keys()):
                vb = self._obj(vid)
                if vb is None:
                    continue
                out.append({
                    "vid": vid,
                    "bv": vb,
                    "filename": self._filename_of(vb) or "",
                    "original": self._original_of(vb) or "",
                })
        out.sort(key=lambda e: int(e["vid"]) if str(e["vid"]).isdigit() else 0)
        return out

    @staticmethod
    def _available(snap) -> list:
        return [
            {
                "view_id": e["vid"],
                "selector": "view:" + e["vid"],
                "filename": e["filename"] or e["original"],
                "basename": _basename(e["filename"] or e["original"]),
            }
            for e in snap
        ]

    @staticmethod
    def _start_hex(bv):
        try:
            return hex(int(bv.start))
        except Exception:
            return None

    def _candidate_start(self, e, read_locked):
        """The start address (hex) of candidate entry `e` of a 409 AMBIGUOUS. `read_locked(view_id, fn)`, when given,
        runs fn under that view's request lock (None when the lock was not acquired in time). Never raises."""
        def _read(bv=e["bv"]):
            return self._start_hex(bv)
        if read_locked is None:
            return _read()
        try:
            return read_locked(e["vid"], _read)
        except Exception:
            return None

    def _pick_one(self, hits, ident, snap, read_locked=None):
        """The one entry of `hits` -> (bv, view_id); none -> 404 NOT_FOUND, several -> 409 AMBIGUOUS."""
        uniq, seen = [], set()
        for e in hits:
            if e["vid"] in seen:
                continue
            seen.add(e["vid"])
            uniq.append(e)
        if len(uniq) == 1:
            return uniq[0]["bv"], uniq[0]["vid"]
        if not uniq:
            raise rc.NotFoundError("binary", ident, self._available(snap))
        cands = [
            {
                "name": e["filename"] or e["original"] or ("view:" + e["vid"]),
                "start": self._candidate_start(e, read_locked),
                "view_id": e["vid"],
                "selector": "view:" + e["vid"],
            }
            for e in uniq
        ]
        raise rc.AmbiguousError("binaries", ident, cands)

    def resolve_binary(self, ident):
        """Strictly resolve a `binary` selector -> (bv, describe_view(bv, 'explicit')).

        locate_binary, then describe_view of the located view. The description reads Binary Ninja (the
        analysis state and, once per file session, the loaded bytes) with whatever lock the CALLER holds:
        a request path that must serialize that work (http_server._dispatch) calls locate_binary, takes
        the view's lock and only then describe_view. Raises what locate_binary raises.
        """
        bv, _vid = self.locate_binary(ident)
        return bv, self.describe_view(bv, "explicit")

    def locate_binary(self, ident, read_locked=None):
        """Strictly resolve a `binary` selector -> (bv, view_id), WITHOUT describing the view.

        Reads only the registry (view ids, filenames, the sorted listing)
        and, for a sha256 selector, the on-disk files' sha256 (_disk_sha256: file I/O, cached). It
        makes no Binary Ninja analysis or content read, so a caller can take the view's request lock
        BEFORE describe_view reads the analysis state and hashes the loaded bytes. The one Binary Ninja
        read it can make is each candidate's start address in a 409 AMBIGUOUS: with `read_locked`
        (callable(view_id, fn) -> fn() run under that view's request lock, or None when the lock was
        not acquired in time) it is read that way, otherwise directly.

        Never touches the global selection. Raises rc.ApiError('BAD_ARGUMENT', 400)
        for an empty or relative-path selector, rc.NotFoundError (404, with `available`) or
        rc.AmbiguousError (409, with `candidates`).
        """
        s = str(ident if ident is not None else "").strip()
        if not s:
            raise rc.ApiError("BAD_ARGUMENT", "empty binary selector", 400)
        snap = self._snapshot()
        # 1. internal view id (all digits is an id, never an ordinal)
        m = _RE_VIEW_ID.match(s)
        vid = m.group(1) if m else (s if _RE_DIGITS.match(s) else None)
        if vid is not None:
            for e in snap:
                if e["vid"] == vid:
                    return e["bv"], e["vid"]
            # A long all-digit string can only otherwise be a sha256 (prefix); short ones are ids.
            if m or len(s) < 12:
                raise rc.NotFoundError("binary", s, self._available(snap))
        # 2. ordinal of the sorted listing
        m = _RE_ORDINAL.match(s)
        if m:
            n = int(m.group(1))
            lst = self.list_open_binaries()
            if 1 <= n <= len(lst):
                target = str(lst[n - 1].get("id") or "")
                for e in snap:
                    if e["vid"] == target:
                        return e["bv"], e["vid"]
            raise rc.NotFoundError("binary", s, self._available(snap))
        stock = snap
        # 3. sha256
        if _RE_HEX64.match(s):
            want = s.lower()
            hits = [e for e in stock if (self._disk_sha256(e["bv"])[0] or "") == want]
            if hits:
                return self._pick_one(hits, s, snap, read_locked)
        # 4. unique sha256 prefix (12-63 hex chars)
        elif _RE_HEXPFX.match(s):
            want = s.lower()
            hits = [e for e in stock if (self._disk_sha256(e["bv"])[0] or "").startswith(want)]
            if hits:
                return self._pick_one(hits, s, snap, read_locked)
        # 5. absolute path (a path-shaped selector must be absolute)
        if "/" in s or "\\" in s:
            if not _is_abs_path(s):
                raise rc.ApiError("BAD_ARGUMENT", "path selector must be absolute", 400,
                                  {"available": self._available(snap)})
            want = _norm_path(s)
            hits = [e for e in stock if want and (want == _norm_path(e["filename"]) or want == _norm_path(e["original"]))]
            return self._pick_one(hits, s, snap, read_locked)
        # 6. unique basename (compared without case on Windows only, _name_key)
        want = _name_key(s)
        hits = [e for e in stock
                if want in ({_name_key(_basename(e["filename"])), _name_key(_basename(e["original"]))} - {""})]
        if hits:
            return self._pick_one(hits, s, snap, read_locked)
        # 7. unique stem, only for an extension-less selector
        if _stem(s) == s:
            hits = [e for e in stock
                    if want in ({_name_key(_stem(_basename(e["filename"]))),
                                 _name_key(_stem(_basename(e["original"])))} - {""})]
            if hits:
                return self._pick_one(hits, s, snap, read_locked)
        raise rc.NotFoundError("binary", s, self._available(snap))

    def view_lock(self, view_id):
        """Re-entrant lock serializing Binary Ninja work on a view.

        lock_mode 'global' (default): every id maps to ONE shared RLock.
        lock_mode 'per-view': one RLock per view id.
        """
        if self.lock_mode != "per-view":
            return self._global_lock
        key = str(view_id or "")
        with self._reg_lock:
            lk = self._view_locks.get(key)
            if lk is None:
                lk = threading.RLock()
                self._view_locks[key] = lk
            return lk

    def is_live(self, view_id) -> bool:
        """Registered, alive and not closing."""
        vid = str(view_id or "")
        if not vid:
            return False
        with self._reg_lock:
            if vid in self._closing or vid not in self._views_by_id:
                return False
            return self._obj(vid) is not None

    def view_id_of(self, bv) -> str:
        """The registered view id of `bv` ('' when it is not registered). Registry only."""
        if bv is None:
            return ""
        with self._reg_lock:
            return self._id_of(bv) or ""

    def live_view(self, view_id, bv=None):
        """The REGISTERED object of `view_id` when the id is registered, alive and not closing (is_live) and,
        with `bv`, still holds bv's view or file session (an id is re-pointed only within one file session,
        e.g. from its Raw view to its analysis view); else None. Registry only (one _reg_lock hold)."""
        vid = str(view_id or "")
        if not vid:
            return None
        with self._reg_lock:
            if vid in self._closing or vid not in self._views_by_id:
                return None
            obj = self._obj(vid)
            if obj is None:
                return None
            if bv is not None and not (self._same(obj, bv) or self._same_session(obj, bv)):
                return None
            return obj

    @contextmanager
    def using_view(self, bv, info=None):
        """Scope the calling thread to `bv` (request_context.scope). Takes no lock."""
        if info is None:
            info = self.describe_view(bv, "explicit")
        with rc.scope(bv, info, False):
            yield bv

    def mark_owned(self, bv) -> str:
        """Register `bv` and keep a strong reference: the server owns (and may close) it."""
        with self._reg_lock:
            vid = self._register_view(bv)
            self._owned[vid] = bv
            if not self._same(self._deref(self._views_by_id.get(vid)), bv):
                self._views_by_id[vid] = weakref.ref(bv)
            return vid

    def raw_patches(self, view_id) -> list:
        """patch_bytes writes recorded for a view this session (copies): every write to the file session
        behind `view_id`, also when it was recorded under an earlier id of that still-open view."""
        with self._reg_lock:
            return [dict(x) for x in self._raw_records(str(view_id or ""))]

    def _record_raw_patch(self, bv, va, orig: bytes, new: bytes) -> None:
        """Record a patch_bytes write: ONE dict appended to the file-session memo's 'raw' list (of `bv` and,
        when it is a different memo, of the registered object of bv's id) and to the per-id mirror."""
        rec = {
            "va": hex(int(va)),
            "len": len(new),
            "orig_hex": (orig or b"").hex(),
            "new_hex": (new or b"").hex(),
        }
        with self._reg_lock:
            vid = self._id_of(bv) or self._register_view(bv)
            memos = []
            for ob in (bv, self._obj(vid) if vid else None):
                if ob is None:
                    continue
                try:
                    m = self._memo_of(ob, self._memo_key(ob))
                except Exception:
                    m = None
                if isinstance(m, dict) and not any(m is x for x in memos):
                    memos.append(m)
            for m in memos:
                m.setdefault("raw", []).append(rec)
            if vid:
                self._raw_patches.setdefault(vid, []).append(rec)

    def close_owned_view(self, view_id) -> dict:
        """Close a server-owned view (a view the server loaded through /load or /x/loadBinary).

        Marks it closing (queued requests then get 410 GONE), waits for its view
        lock (re-entrant: safe when the caller is scoped to that view; bounded by
        lock_wait_s, else 503 BUSY), closes the file OUTSIDE the registry lock and
        unregisters it.
        """
        vid = str(view_id or "").strip()
        with self._reg_lock:
            if vid not in self._owned:
                if vid in self._views_by_id:
                    raise rc.ApiError(
                        "POLICY",
                        f"view {vid} is not owned by the MCP server; only views it loaded (/load, /x/loadBinary) "
                        "can be closed through it",
                        403,
                    )
                raise rc.NotFoundError("owned binary", vid or "(empty)")
            if vid in self._closing:
                raise rc.GoneError("binary", vid)
            self._closing.add(vid)
            bv = self._owned.get(vid)
            fn = self._filename_of(bv) or ""
        lk = self.view_lock(vid)
        if not _acquire(lk, self.lock_wait_s):
            with self._reg_lock:
                self._closing.discard(vid)
            raise rc.ApiError("BUSY", f"view {vid} is busy; close not attempted", 503, {"retry_after_s": 5})
        close_err = None
        try:
            mk = self._memo_key(bv)   # before the close (never raises)
            try:
                if bv is not None and getattr(bv, "file", None) is not None:
                    bv.file.close()
            except Exception as e:
                close_err = str(e)
                bn.log_warn(f"close_owned_view({vid}): file.close failed: {e}")
            with self._reg_lock:
                self._views_by_id.pop(vid, None)
                self._owned.pop(vid, None)
                self._raw_patches.pop(vid, None)
                self._stat_at_reg.pop(vid, None)
                if bv is not None:
                    self._forget_memo(bv, mk)
                for k in [k for k, v in self._id_by_filename.items() if v == vid]:
                    self._id_by_filename.pop(k, None)
                if self._global_view is not None and self._same(self._global_view, bv):
                    self._global_view = None
                self._closing.discard(vid)
                self._view_locks.pop(vid, None)
        finally:
            lk.release()
        return {"closed": True, "view_id": vid, "filename": fn, "close_error": close_err}

    def _dedupe_funcs(self, funcs) -> list:
        out, seen = [], set()
        for f in funcs:
            try:
                arch = getattr(getattr(f, "arch", None), "name", None)
                key = (int(f.start), str(arch))
            except Exception:
                key = ("id", id(f))
            if key in seen:
                continue
            seen.add(key)
            out.append(f)
        return out

    def _raise_ambiguous_functions(self, identifier, funcs):
        cands = []
        for f in sorted(funcs, key=lambda x: int(getattr(x, "start", 0) or 0)):
            try:
                cands.append({"name": f.name, "start": hex(int(f.start)),
                              "arch": str(getattr(getattr(f, "arch", None), "name", "") or "")})
            except Exception:
                continue
        err = rc.AmbiguousError("functions", identifier, cands)
        rc.note_ambiguity(err)
        bn.log_error(str(err))
        raise err

    def get_function_by_name_or_address(
        self, identifier: Union[str, int]
    ) -> Optional[bn.Function]:
        """Get a function by either its name or address.

        Args:
            identifier: Function name or address (can be int, hex string, or decimal string)

        Returns:
            Function object if found, None otherwise

        Raises:
            request_context.AmbiguousError (409) when a name matches more than one
            function (never a silent first-match guess).
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        # Handle address-based lookup
        try:
            if isinstance(identifier, str) and identifier.startswith("0x"):
                addr = int(identifier, 16)
            elif isinstance(identifier, (int, str)):
                addr = int(identifier) if isinstance(identifier, str) else identifier

            func = self._current_view.get_function_at(addr)
            if func:
                bn.log_debug(f"Found function at address {hex(addr)}: {func.name}")
                return func
        except ValueError:
            pass

        bv = self._current_view
        ident_s = str(identifier)

        # Exact name: union of the symbol index and an exact scan, deduplicated by (start, arch)
        exact = []
        try:
            by_name = getattr(bv, "get_functions_by_name", None)
            if callable(by_name):
                exact.extend(list(by_name(ident_s) or []))
        except Exception:
            pass
        for func in bv.functions:
            if func.name == identifier:
                exact.append(func)
        exact = self._dedupe_funcs(exact)
        if len(exact) == 1:
            bn.log_debug(f"Found function by name: {exact[0].name}")
            return exact[0]
        if len(exact) > 1:
            self._raise_ambiguous_functions(identifier, exact)

        # Try case-insensitive match as fallback (unique, else ambiguous)
        low = ident_s.lower()
        ci = self._dedupe_funcs([f for f in bv.functions if f.name.lower() == low])
        if len(ci) == 1:
            bn.log_debug(f"Found function by case-insensitive name: {ci[0].name}")
            return ci[0]
        if len(ci) > 1:
            self._raise_ambiguous_functions(identifier, ci)

        # Try symbol table lookup as last resort
        symbol = self._current_view.get_symbol_by_raw_name(str(identifier))
        if symbol and symbol.address:
            func = self._current_view.get_function_at(symbol.address)
            if func:
                bn.log_debug(f"Found function through symbol lookup: {func.name}")
                return func

        bn.log_error(f"Could not find function: {identifier}")
        return None

    def get_function_names(
        self, offset: int = 0, limit: int = 100
    ) -> List[Dict[str, str]]:
        """Get list of function names with addresses"""
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        functions = []
        for func in self._current_view.functions:
            functions.append(
                {
                    "name": func.name,
                    "address": hex(func.start),
                    "raw_name": func.raw_name
                    if hasattr(func, "raw_name")
                    else func.name,
                }
            )

        return functions[offset : offset + limit]

    def get_class_names(self, offset: int = 0, limit: int = 100) -> List[str]:
        """Get list of class names with pagination"""
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        class_names = set()

        try:
            # Try different methods to identify classes
            for type_obj in self._current_view.types.values():
                try:
                    # Skip None or invalid types
                    if not type_obj or not hasattr(type_obj, "name"):
                        continue

                    # Method 1: Check type_class attribute
                    if hasattr(type_obj, "type_class"):
                        class_names.add(type_obj.name)
                        continue

                    # Method 2: Check structure attribute
                    if hasattr(type_obj, "structure") and type_obj.structure:
                        structure = type_obj.structure

                        # Check various attributes that indicate a class
                        if any(
                            hasattr(structure, attr)
                            for attr in [
                                "vtable",
                                "base_structures",
                                "members",
                                "functions",
                            ]
                        ):
                            class_names.add(type_obj.name)
                            continue

                        # Check type attribute if available
                        if hasattr(structure, "type"):
                            type_str = str(structure.type).lower()
                            if "class" in type_str or "struct" in type_str:
                                class_names.add(type_obj.name)
                                continue

                except Exception as e:
                    bn.log_debug(
                        f"Error processing type {getattr(type_obj, 'name', '<unknown>')}: {e}"
                    )
                    continue

            bn.log_debug(f"Found {len(class_names)} classes")
            sorted_names = sorted(list(class_names))
            return sorted_names[offset : offset + limit]

        except Exception as e:
            bn.log_error(f"Error getting class names: {e}")
            return []

    def get_segments(self, offset: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
        """Get list of segments with pagination"""
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        segments = []
        for segment in self._current_view.segments:
            segment_info = {
                "start": hex(segment.start),
                "end": hex(segment.end),
                "name": "",
                "flags": [],
            }

            # Try to get segment name if available
            if hasattr(segment, "name"):
                segment_info["name"] = segment.name
            elif hasattr(segment, "data_name"):
                segment_info["name"] = segment.data_name

            # Try to get segment flags safely
            if hasattr(segment, "flags"):
                try:
                    if isinstance(segment.flags, (list, tuple)):
                        segment_info["flags"] = list(segment.flags)
                    else:
                        segment_info["flags"] = [str(segment.flags)]
                except (AttributeError, TypeError, ValueError):
                    pass

            # Add segment permissions if available
            if hasattr(segment, "readable"):
                segment_info["readable"] = bool(segment.readable)
            if hasattr(segment, "writable"):
                segment_info["writable"] = bool(segment.writable)
            if hasattr(segment, "executable"):
                segment_info["executable"] = bool(segment.executable)

            segments.append(segment_info)

        return segments[offset : offset + limit]

    def get_sections(self, offset: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
        """Get list of sections with pagination.

        Returns per-section fields when available:
        - name: section name
        - start/end: hex strings
        - size: integer number of bytes (end - start)
        - type: stringified section type (if exposed by BN)
        - semantics: stringified semantics (if exposed by BN)
        - linked_section: related/paired section name if exposed
        - alignment: alignment in bytes if exposed
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        results: List[Dict[str, Any]] = []

        # Binary Ninja has exposed sections across versions either as an
        # iterable of Section objects or a dict-like object. Handle both.
        try:
            sec_container = getattr(self._current_view, "sections", None)
        except Exception:
            sec_container = None
        if not sec_container:
            return []

        def _iter_sections(container):
            try:
                # If it's a dict-like {name: Section}
                if hasattr(container, "items"):
                    for _name, _sec in list(container.items()):
                        yield _sec
                    return
            except Exception:
                pass
            # Otherwise assume it's iterable of Section objects
            try:
                for _sec in list(container):
                    yield _sec
            except Exception:
                return

        for sec in _iter_sections(sec_container):
            try:
                start = getattr(sec, "start", None)
                end = getattr(sec, "end", None)
                if start is None or end is None:
                    continue
                name = None
                try:
                    name = getattr(sec, "name", None)
                except Exception:
                    name = None
                try:
                    size = int(end) - int(start)
                except Exception:
                    size = None

                entry: Dict[str, Any] = {
                    "name": name or "",
                    "start": hex(int(start)),
                    "end": hex(int(end)),
                    "size": size,
                }

                # Optional attributes: type, semantics, linked_section, alignment
                for attr, key in (
                    ("type", "type"),
                    ("semantics", "semantics"),
                    ("linked_section", "linked_section"),
                    ("align", "alignment"),
                    ("alignment", "alignment"),
                ):
                    try:
                        val = getattr(sec, attr, None)
                        if val is not None:
                            entry[key] = str(val)
                    except Exception:
                        pass

                results.append(entry)
            except Exception:
                continue

        return results[offset : offset + limit]

    def rename_function(self, old_name: str, new_name: str) -> bool:
        """Rename a function using multiple fallback methods.

        Args:
            old_name: Current function name or address
            new_name: New name for the function

        Returns:
            True if rename succeeded, False otherwise
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        try:
            func = self.get_function_by_name_or_address(old_name)
            if not func:
                bn.log_error(f"Function not found: {old_name}")
                return False

            bn.log_debug(f"Found function to rename: {func.name} at {hex(func.start)}")

            if not new_name or not isinstance(new_name, str):
                bn.log_error("rename_function: the new name is empty or invalid")
                return False

            if not hasattr(func, "name") or not hasattr(func, "__setattr__"):
                bn.log_error(f"Function {func.name} cannot be renamed (read-only)")
                return False

            try:
                # Try direct name assignment first
                old_name = func.name
                func.name = new_name

                if func.name == new_name:
                    bn.log_debug(f"Renamed the function at {hex(func.start)}")
                    return True

                # Try symbol-based renaming if direct assignment fails
                if hasattr(func, "symbol") and func.symbol:
                    try:
                        new_symbol = bn.Symbol(
                            func.symbol.type,
                            func.start,
                            new_name,
                            namespace=func.symbol.namespace
                            if hasattr(func.symbol, "namespace")
                            else None,
                        )
                        self._current_view.define_user_symbol(new_symbol)
                        bn.log_debug("Successfully renamed function using symbol table")
                        return True
                    except Exception as e:
                        bn.log_error(f"Symbol-based rename failed: {e}")

                # Try function update method as last resort
                if hasattr(self._current_view, "update_function"):
                    try:
                        func_copy = func
                        func_copy.name = new_name
                        self._current_view.update_function(func)
                        bn.log_debug("Successfully renamed function using update method")
                        return True
                    except Exception as e:
                        bn.log_error(f"Function update rename failed: {e}")

                bn.log_error(
                    f"All rename methods failed - function name unchanged: {func.name}"
                )
                return False

            except Exception as e:
                bn.log_error(f"Error during rename operation: {e}")
                return False

        except Exception as e:
            bn.log_error(f"Error in rename_function: {e}")
            return False

    def get_function_info(
        self, identifier: Union[str, int]
    ) -> Optional[Dict[str, Any]]:
        """Get detailed information about a function"""
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        func = self.get_function_by_name_or_address(identifier)
        if not func:
            return None

        bn.log_debug(f"Found function: {func.name} at {hex(func.start)}")

        info = {
            "name": func.name,
            "raw_name": func.raw_name if hasattr(func, "raw_name") else func.name,
            "address": hex(func.start),
            "symbol": None,
        }

        if func.symbol:
            info["symbol"] = {
                "type": str(func.symbol.type),
                "full_name": func.symbol.full_name
                if hasattr(func.symbol, "full_name")
                else func.symbol.name,
            }

        return info

    @staticmethod
    def _skip_reason(func) -> str:
        try:
            r = func.analysis_skip_reason
            return str(getattr(r, "name", None) or r)
        except Exception:
            return "unknown"

    @staticmethod
    def _format_il_lines(pairs, func) -> str:
        lines: list[str] = []
        last_addr: Optional[int] = None
        for addr, text in pairs:
            if addr is None:
                addr = last_addr if last_addr is not None else func.start
            last_addr = addr
            lines.append(f"{int(addr):08x}        {text}")
        return "\n".join(lines)

    def _render_ast(self, func, il: str, ssa: bool) -> Optional[str]:
        """render='ast': expert_ops.render_function_lines, formatted like the legacy
        '<addr>        <text>' lines. Returns None (after rc.warn('render-fallback'))
        on any failure so the caller falls back to the legacy rendering."""
        try:
            from .expert_ops import render_function_lines
            lines, _render_used = render_function_lines(self._current_view, func, il, ssa, "ast")
            pairs = [(item[0], item[1]) for item in (lines or [])]
            if not pairs:
                raise ValueError("empty rendering")
            return self._format_il_lines(pairs, func)
        except Exception:
            rc.warn("render-fallback")
            return None

    def decompile_function(self, identifier: Union[str, int], render: str = "legacy", force_analysis: bool = True) -> Optional[str]:
        """Decompile a function and include addresses per statement.

        Args:
            identifier: Function name or address
            render: 'legacy' (default; upstream output) or 'ast' (expert_ops AST lines,
                falling back to legacy with a 'render-fallback' warning)
            force_analysis: True (default; upstream behaviour) re-enables a skipped
                function and waits for view analysis when HLIL is missing. False never
                mutates analysis_skipped and never waits on the whole view; missing IL
                adds a 'no-il: <skip reason>' warning.

        Returns:
            Decompiled HLIL-like code with address prefixes per line
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        func = self.get_function_by_name_or_address(identifier)
        if not func:
            return None

        if force_analysis:
            # analyze func only if IL is not already available (update_analysis_and_wait blocks on
            # whole-view analysis and mutates persistent analysis_skipped state on a read path)
            if getattr(func, "hlil", None) is None:
                func.analysis_skipped = False
                self._current_view.update_analysis_and_wait()
        elif getattr(func, "hlil", None) is None:
            rc.warn("no-il: " + self._skip_reason(func))

        if str(render or "").strip().lower() == "ast":
            out = self._render_ast(func, "hlil", False)
            if out is not None:
                return out

        try:
            il = getattr(func, "hlil", None)
            if il and hasattr(il, "instructions"):
                lines: list[str] = []
                last_addr: Optional[int] = None
                for ins in il.instructions:
                    try:
                        addr = getattr(ins, "address", None)
                    except Exception:
                        addr = None
                    if addr is None:
                        addr = last_addr if last_addr is not None else func.start
                    last_addr = addr
                    addr_str = f"{int(addr):08x}"
                    text = str(ins)
                    lines.append(f"{addr_str}        {text}")
                return "\n".join(lines)
            # Fall back to MLIL with addresses
            mil = getattr(func, "mlil", None)
            if mil and hasattr(mil, "instructions"):
                lines: list[str] = []
                last_addr: Optional[int] = None
                for ins in mil.instructions:
                    try:
                        addr = getattr(ins, "address", None)
                    except Exception:
                        addr = None
                    if addr is None:
                        addr = last_addr if last_addr is not None else func.start
                    last_addr = addr
                    addr_str = f"{int(addr):08x}"
                    text = str(ins)
                    lines.append(f"{addr_str}        {text}")
                return "\n".join(lines)
            # Last resort
            return str(func)
        except Exception as e:
            bn.log_error(f"Error decompiling function: {str(e)}")
            return None

    def get_function_il(self, identifier: Union[str, int], view: str = "hlil", ssa: bool = False,
                        render: str = "legacy", force_analysis: bool = True) -> Optional[str]:
        """Return IL for a function with selectable view and optional SSA form.

        Args:
            identifier: Function name or address
            view: One of 'hlil', 'mlil', 'llil' (case-insensitive). Aliases: 'il' -> 'llil'.
            ssa: When True, use SSA form if available (MLIL/LLIL only)
            render: 'legacy' (default) or 'ast' (see decompile_function)
            force_analysis: see decompile_function (default True = upstream behaviour)

        Returns:
            Concatenated string with one instruction per line prefixed by address.
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        func = self.get_function_by_name_or_address(identifier)
        if not func:
            return None

        # Ensure analysis has run only if IL is missing (update_analysis_and_wait blocks on
        # whole-view analysis and mutates persistent analysis_skipped state)
        if force_analysis:
            try:
                if getattr(func, "hlil", None) is None:
                    func.analysis_skipped = False
                    self._current_view.update_analysis_and_wait()
            except Exception:
                pass

        v = (view or "").strip().lower()
        if v in ("il", "llil", "low", "lowlevel", "low-level", "low_level"):
            prop = "llil"
        elif v in ("mlil", "medium", "mediumlevel", "medium-level", "medium_level"):
            prop = "mlil"
        else:
            # Default to HLIL when unknown
            prop = "hlil"

        if not force_analysis:
            try:
                if getattr(func, prop, None) is None:
                    rc.warn("no-il: " + self._skip_reason(func))
            except Exception:
                pass

        if str(render or "").strip().lower() == "ast":
            out = self._render_ast(func, prop, bool(ssa))
            if out is not None:
                return out

        try:
            il_func = getattr(func, prop, None)
            if il_func is None:
                return None

            # Only MLIL/LLIL support SSA form in practice
            if ssa and hasattr(il_func, "ssa_form") and il_func.ssa_form is not None:
                il_func = il_func.ssa_form

            if not hasattr(il_func, "instructions"):
                # As a last resort, stringify the object
                return str(il_func)

            lines: list[str] = []
            last_addr: Optional[int] = None
            for ins in il_func.instructions:
                try:
                    addr = getattr(ins, "address", None)
                except Exception:
                    addr = None
                if addr is None:
                    addr = last_addr if last_addr is not None else func.start
                last_addr = addr
                addr_str = f"{int(addr):08x}"
                text = str(ins)
                lines.append(f"{addr_str}        {text}")
            return "\n".join(lines)
        except Exception as e:
            bn.log_error(f"Error getting {prop}{' SSA' if ssa else ''} for function {identifier}: {str(e)}")
            return None

    def rename_data(self, address: int, new_name: str) -> bool:
        """Rename data at a specific address"""
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        try:
            if self._current_view.is_valid_offset(address):
                self._current_view.define_user_symbol(
                    bn.Symbol(bn.SymbolType.DataSymbol, address, new_name)
                )
                return True
        except Exception as e:
            bn.log_error(f"Failed to rename data: {e}")
        return False

    def make_function_at(self, address: str | int, architecture: str | None = None) -> Dict[str, Any]:
        """Create a function at the given address (no-op if it already exists).

        Args:
            address: Hex string (e.g., 0x401000) or integer address.
            architecture: Optional architecture name (e.g., "x86_64", "x86", "armv7").

        Returns:
            Dict with keys: status (ok|exists), address, name (if found), architecture (if resolved).

        Raises:
            RuntimeError if no binary is loaded.
            ValueError on invalid address or creation failure.
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        # Parse address
        try:
            if isinstance(address, str) and address.lower().startswith("0x"):
                addr = int(address, 16)
            else:
                addr = int(address)
        except Exception:
            raise ValueError(f"Invalid address: {address}")

        bv = self._current_view

        # If a function already exists, return info
        try:
            existing = bv.get_function_at(addr)
            if existing:
                return {
                    "status": "exists",
                    "address": hex(addr),
                    "name": existing.name,
                    "architecture": str(getattr(existing, "arch", getattr(bv, "arch", ""))) or None,
                }
        except Exception:
            pass

        # Resolve platform if provided; otherwise use view/platform default.
        # Note: BinaryView.create_user_function expects a Platform, not an Architecture.
        plat_obj = None
        arch_token = None
        if isinstance(architecture, str):
            arch_token = architecture.strip().lower()
        if architecture and arch_token not in (None, "", "default", "auto", "platform"):
            try:
                P = getattr(__import__('binaryninja', fromlist=['Platform']), 'Platform', None)
            except Exception:
                P = None
            if P is not None:
                try:
                    plat_obj = P[architecture]
                except Exception:
                    try:
                        getp = getattr(P, 'get_by_name', None)
                        if callable(getp):
                            plat_obj = getp(architecture)
                    except Exception:
                        plat_obj = None
            # If user explicitly provided an architecture/platform name and we couldn't resolve it,
            # return an error with suggestions instead of silently using the default.
            if plat_obj is None:
                import re as _re
                from difflib import get_close_matches as _gcm
                names: list[str] = []
                # Prefer dynamic enumeration via binaryninja.Platform
                try:
                    import binaryninja as _bn  # type: ignore
                    try:
                        names = [str(getattr(p, 'name', str(p))) for p in list(getattr(_bn, 'Platform'))]
                    except Exception:
                        names = []
                except Exception:
                    names = []
                # Fallback: try iterating via imported P if available
                if not names and P is not None:
                    try:
                        names = [str(getattr(p, 'name', str(p))) for p in list(P)]
                    except Exception:
                        names = []
                # Last resort: static catalog (kept up-to-date best-effort)
                if not names:
                    names = [
                        'decree-x86','efi-x86','efi-windows-x86','efi-x86_64','efi-windows-x86_64','efi-aarch64','efi-windows-aarch64','efi-armv7','efi-thumb2',
                        'freebsd-x86','freebsd-x86_64','freebsd-aarch64','freebsd-armv7','freebsd-thumb2',
                        'ios-aarch64','ios-armv7','ios-thumb2','ios-kernel-aarch64','ios-kernel-armv7','ios-kernel-thumb2',
                        'linux-ppc32','linux-ppcvle32','linux-ppc64','linux-ppc32_le','linux-ppc64_le','linux-rv32gc','linux-rv64gc',
                        'linux-x86','linux-x86_64','linux-x32','linux-aarch64','linux-armv7','linux-thumb2','linux-armv7eb','linux-thumb2eb',
                        'linux-mipsel','linux-mips','linux-mips3','linux-mipsel3','linux-mips64','linux-cnmips64','linux-mipsel64',
                        'mac-x86','mac-x86_64','mac-aarch64','mac-armv7','mac-thumb2','mac-kernel-x86','mac-kernel-x86_64','mac-kernel-aarch64','mac-kernel-armv7','mac-kernel-thumb2',
                        'windows-x86','windows-x86_64','windows-aarch64','windows-armv7','windows-thumb2','windows-kernel-x86','windows-kernel-x86_64','windows-kernel-windows-aarch64',
                    ]
                # Build ranked suggestions
                tl = (arch_token or "").lower()
                def _score(n: str) -> float:
                    nl = n.lower()
                    s = 0.0
                    if tl and tl in nl:
                        s += 2.0
                    # remove non-alnum for loose matching
                    tlr = _re.sub(r"[^a-z0-9]", "", tl)
                    nlr = _re.sub(r"[^a-z0-9]", "", nl)
                    if tlr and tlr in nlr:
                        s += 1.0
                    return s
                base = sorted(names)
                # Start with substring matches, then extend with close matches
                substr = [n for n in base if tl in n.lower()]
                # Use difflib for additional candidates if needed
                extra = _gcm(tl, base, n=10, cutoff=0.3) if tl else []
                cand = []
                seen = set()
                for n in substr + extra:
                    if n not in seen:
                        seen.add(n)
                        cand.append(n)
                cand.sort(key=_score, reverse=True)
                similar = ", ".join(cand[:10])
                raise ValueError(f"Unknown platform/architecture '{architecture}'"
                                 + (f"; similar names: {similar}" if similar else ""))
        # Default/platform fallback when no explicit architecture provided
        if plat_obj is None:
            try:
                plat_obj = getattr(bv, 'platform', None)
            except Exception:
                plat_obj = None

        # Create the function
        try:
            if hasattr(bv, 'create_user_function'):
                if plat_obj is not None:
                    bv.create_user_function(addr, plat_obj)
                else:
                    bv.create_user_function(addr)
            elif hasattr(bv, 'add_function'):
                if plat_obj is not None:
                    bv.add_function(addr, plat_obj)
                else:
                    bv.add_function(addr)
            else:
                raise ValueError('BinaryView does not support function creation')
        except Exception as e:
            raise ValueError(f"Failed to create function: {str(e)}")

        # Fetch created function info
        try:
            fn = bv.get_function_at(addr)
        except Exception:
            fn = None
        return {
            "status": "ok",
            "address": hex(addr),
            "name": fn.name if fn else None,
            "platform": str(plat_obj) if plat_obj is not None else None,
            "architecture": str(getattr(plat_obj, 'arch', None)) if plat_obj is not None else (str(getattr(bv, 'arch', None)) if getattr(bv, 'arch', None) is not None else None),
        }

    def get_defined_data(
        self, offset: int = 0, limit: int = 100, read_len: int = 32
    ) -> List[Dict[str, Any]]:
        """Get list of defined data variables with lightweight previews and sizes.

        Returns per-item fields:
        - address: hex string
        - name/raw_name: label info if available
        - type: string if available
        - size: exact defined size in bytes if known (from BN type)
        - width: alias of size for backward compatibility
        - value: small integer value when width<=8 and readable; otherwise None
        - bytes_hex: hex string of up to preview_len bytes
        - ascii_preview: printable ASCII representation for the same bytes
        - repr: concise, human-friendly summary for LLMs (value/ASCII/hex)
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        data_items = []
        for var in self._current_view.data_vars:
            data_type = None  # may be a BN Type or a DataVariable
            value = None
            width = None
            bytes_hex = None
            ascii_preview = None
            typ_obj = None

            try:
                # Prefer DataVariable (carries underlying Type)
                dv = None
                if hasattr(self._current_view, "get_data_var_at"):
                    try:
                        dv = self._current_view.get_data_var_at(var)
                    except Exception:
                        dv = None
                if dv is not None and hasattr(dv, "type") and dv.type is not None:
                    typ_obj = dv.type
                    data_type = dv  # keep for fallback string formatting
                else:
                    # Fall back to direct type lookup
                    if hasattr(self._current_view, "get_type_at"):
                        try:
                            typ_obj = self._current_view.get_type_at(var)
                            data_type = typ_obj
                        except Exception:
                            typ_obj = None

                # Exact defined size if available
                if typ_obj is not None and hasattr(typ_obj, "width"):
                    try:
                        width = int(typ_obj.width)
                    except Exception:
                        width = None

                # Best-effort numeric read for small integers (<= 8 bytes)
                if width is not None and width <= 8:
                    try:
                        value = str(self._current_view.read_int(var, width))
                    except (ValueError, RuntimeError):
                        value = None

                # Provide bytes + ASCII preview for all cases
                # Determine effective read length
                try:
                    requested = int(read_len)
                except Exception:
                    requested = 32
                # If requested < 0 and width known, treat as "read exact size"
                if requested < 0 and width is not None:
                    eff_len = max(0, int(width))
                else:
                    eff_len = max(0, requested if requested >= 0 else 32)
                if width is not None:
                    eff_len = min(eff_len, int(width))

                try:
                    raw = self._current_view.read(var, eff_len)
                    if raw is not None:
                        try:
                            bytes_hex = raw.hex()
                        except Exception:
                            bytes_hex = None
                        try:
                            ascii_preview = "".join(chr(b) if 32 <= b <= 126 else "." for b in raw)
                        except Exception:
                            ascii_preview = None
                except (ValueError, RuntimeError, TypeError):
                    pass
            except (AttributeError, TypeError, ValueError, RuntimeError):
                value = None
                data_type = None
                typ_obj = None

            # NOTE: do NOT infer size here. infer_data_size() walks every function's HLIL across
            # the whole binary; calling it once per untyped data var is an
            # O(data_vars * functions * instructions) hang. Report size=None instead; callers
            # needing inference can call infer_data_size for a single address.

            # Get symbol information
            sym = self._current_view.get_symbol_at(var)
            # Choose a concise repr for LLMs
            if value is not None:
                short_repr = f"int:{value}"
            elif ascii_preview:
                short_repr = f"ascii:\"{ascii_preview}\""
            elif bytes_hex:
                short_repr = f"hex:{bytes_hex}"
            else:
                short_repr = None

            data_items.append(
                {
                    "address": hex(var),
                    "name": sym.name if sym else "(unnamed)",
                    "raw_name": sym.raw_name if sym and hasattr(sym, "raw_name") else None,
                    # Prefer clean type string (avoid "<var ...>" envelope when possible)
                    "type": (str(typ_obj) if typ_obj is not None else (str(data_type) if data_type else None)),
                    "size": width,
                    "width": width,
                    "value": value,
                    "bytes_hex": bytes_hex,
                    "ascii_preview": ascii_preview,
                    "bytes_read": len(bytes_hex)//2 if bytes_hex else 0,
                    "repr": short_repr,
                }
            )

        return data_items[offset : offset + limit]

    def infer_data_size(self, address: int) -> Optional[int]:
        """Infer size for data at address when BN hasn't defined a type width.

        Strategy:
        - Prefer BN's DataVariable.type.width or get_type_at().width if available.
        - Otherwise scan HLIL for calls like memcmp/strncmp/memcpy/strncpy where
          an argument equals this address and extract the last numeric argument
          as a best-effort length. Returns the maximum constant seen.
        """
        if not self._current_view:
            return None

        # 1) BN-provided width if available
        try:
            dv = None
            if hasattr(self._current_view, "get_data_var_at"):
                dv = self._current_view.get_data_var_at(address)
            t = None
            if dv is not None and hasattr(dv, "type"):
                t = dv.type
            elif hasattr(self._current_view, "get_type_at"):
                t = self._current_view.get_type_at(address)
            if t is not None and hasattr(t, "width") and t.width:
                return int(t.width)
        except Exception:
            pass

        # 2) HLIL heuristic: only inspect functions that actually reference this
        #    address (indexed via get_code_refs); never scan the whole binary,
        #    which hangs on large binaries. Fall back to the legacy whole-binary
        #    scan only on small binaries where it cannot hang.
        try:
            addr_hex = hex(address)
            candidates: List[int] = []
            names = ("memcmp", "strncmp", "memcpy", "strncpy")
            funcs_to_scan: List[Any] = []
            try:
                seen_starts = set()
                for ref in self._current_view.get_code_refs(address):
                    fn = getattr(ref, "function", None)
                    start = getattr(fn, "start", None)
                    if fn is not None and start not in seen_starts:
                        seen_starts.add(start)
                        funcs_to_scan.append(fn)
                    if len(funcs_to_scan) >= 256:
                        break
            except Exception:
                funcs_to_scan = []
            # Only fall back to the whole-binary scan on small binaries.
            if not funcs_to_scan and not self._xref_is_large_binary():
                funcs_to_scan = self._current_view.functions
            for func in funcs_to_scan:
                try:
                    il = getattr(func, "hlil", None)
                    if not il:
                        continue
                    for ins in il.instructions:
                        try:
                            text = str(ins)
                            if addr_hex not in text:
                                continue
                            if not any(n in text for n in names):
                                continue
                            # Extract all numeric constants
                            nums = re.findall(r"0x[0-9a-fA-F]+|\b\d+\b", text)
                            vals: List[int] = []
                            for n in nums:
                                try:
                                    v = int(n, 16) if n.startswith("0x") else int(n)
                                    vals.append(v)
                                except Exception:
                                    continue
                            if vals:
                                # Heuristic: last constant in call string is likely the size
                                candidates.append(vals[-1])
                        except Exception:
                            continue
                except Exception:
                    continue
            if candidates:
                # Use the maximum plausible size
                best = max(c for c in candidates if c > 0)
                if best > 0:
                    return best
        except Exception:
            pass
        return None

    def list_local_types(self, offset: int = 0, limit: int = 100, include_libraries: bool = False) -> List[Dict[str, Any]]:
        """List local types (Types view) in the current database.

        Returns a list of dictionaries with:
        - name: type name
        - kind: struct/union/class/enum/typedef/unknown
        - decl: string form of the type (when available)
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        results: List[Dict[str, Any]] = []
        seen_keys = set()
        try:
            def add_type_entry(name, tobj):
                # Normalize name to string to avoid BN QualifiedName in JSON
                try:
                    name_str = str(name) if name is not None else None
                except Exception:
                    name_str = None
                if not name_str:
                    return
                # Fallback: try to resolve missing type object by querying BV / libraries
                if tobj is None:
                    try:
                        if hasattr(self._current_view, "get_type_by_name"):
                            t2 = self._current_view.get_type_by_name(name_str)
                            if t2 is not None:
                                tobj = t2
                    except Exception:
                        pass
                    if tobj is None:
                        try:
                            plat = getattr(self._current_view, "platform", None)
                            libs = list(getattr(plat, "type_libraries", []) or []) if plat else []
                            for lib in libs:
                                get_t = getattr(lib, "get_type_by_name", None)
                                if not callable(get_t):
                                    continue
                                t3 = None
                                try:
                                    # Try QualifiedName if available
                                    try:
                                        t3 = get_t(bn.QualifiedName(name_str))
                                    except Exception:
                                        t3 = get_t(name_str)
                                except Exception:
                                    t3 = None
                                if t3 is not None:
                                    tobj = t3
                                    break
                        except Exception:
                            pass

                tc = getattr(tobj, "type_class", None)
                kind = "unknown"
                if tc == TypeClass.VoidTypeClass:
                    kind = "void"
                elif tc == TypeClass.BoolTypeClass:
                    kind = "bool"
                elif tc == TypeClass.IntegerTypeClass:
                    kind = "int"
                elif tc == TypeClass.FloatTypeClass:
                    kind = "float"
                elif tc == TypeClass.StructureTypeClass:
                    try:
                        if getattr(tobj, "type", None) == StructureVariant.StructStructureType:
                            kind = "struct"
                        elif getattr(tobj, "type", None) == StructureVariant.UnionStructureType:
                            kind = "union"
                        elif getattr(tobj, "type", None) == StructureVariant.ClassStructureType:
                            kind = "class"
                        else:
                            kind = "struct"
                    except Exception:
                        kind = "struct"
                elif tc == TypeClass.EnumerationTypeClass:
                    kind = "enum"
                elif tc == TypeClass.NamedTypeReferenceClass:
                    kind = "typedef"
                elif tc == TypeClass.FunctionTypeClass:
                    kind = "function"
                elif tc == TypeClass.WideCharTypeClass:
                    kind = "wchar"
                elif tc == TypeClass.PointerTypeClass:
                    kind = "pointer"
                elif tc == TypeClass.ArrayTypeClass:
                    kind = "array"

                decl = None
                try:
                    decl = str(tobj)
                except Exception:
                    try:
                        decl = str(getattr(tobj, "type", None))
                    except Exception:
                        decl = None

                # If kind is unknown or a named typedef, try to infer underlying from declaration text
                try:
                    dlow = (decl or "").strip().lower()
                    if dlow:
                        if dlow.startswith("struct ") or " struct " in dlow:
                            kind = "struct"
                        elif dlow.startswith("union ") or " union " in dlow:
                            kind = "union"
                        elif dlow.startswith("enum ") or " enum " in dlow:
                            kind = "enum"
                except Exception:
                    pass

                key = (name_str, decl or "")
                if key in seen_keys:
                    return
                results.append({
                    "name": name_str,
                    "kind": kind,
                    "type_class": str(tc) if tc is not None else None,
                    "decl": decl,
                })
                seen_keys.add(key)

            # Source 1: user_type_container (explicit local/user types)
            try:
                utc = getattr(self._current_view, "user_type_container", None)
                if utc and getattr(utc, "types", None):
                    for type_id in list(utc.types.keys()):
                        try:
                            entry = utc.types[type_id]
                            name = entry[0] if isinstance(entry, (tuple, list)) else getattr(entry, "name", None)
                            tobj = entry[1] if isinstance(entry, (tuple, list)) else getattr(entry, "type", entry)
                            add_type_entry(name, tobj)
                        except Exception:
                            continue
            except Exception:
                pass

            # Source 2: view.types (BN view-local types)
            for k, v in self._current_view.types.items():
                try:
                    if isinstance(v, (tuple, list)) and len(v) >= 2:
                        name = str(v[0])
                        tobj = v[1]
                    else:
                        tobj = v
                        name = getattr(v, "name", None)
                        if not name:
                            name = str(k)
                    add_type_entry(name, tobj)
                except Exception:
                    continue

            # Source 3: platform type libraries (optional; can be heavy)
            if include_libraries:
                try:
                    plat = getattr(self._current_view, "platform", None)
                    libs = []
                    try:
                        libs = list(getattr(plat, "type_libraries", []) or [])
                    except Exception:
                        libs = []
                    for lib in libs:
                        # Try multiple ways to enumerate names in this library
                        names = []
                        try:
                            nt = getattr(lib, "named_types", None)
                            if isinstance(nt, dict):
                                names = list(nt.keys())
                        except Exception:
                            pass
                        if not names:
                            try:
                                tmap = getattr(lib, "types", None)
                                if isinstance(tmap, dict):
                                    names = list(tmap.keys())
                            except Exception:
                                pass
                        if not names:
                            try:
                                get_names = getattr(lib, "get_type_names", None)
                                if callable(get_names):
                                    names = list(get_names())
                            except Exception:
                                pass
                        # Fetch each type object if possible
                        for nm in names:
                            try:
                                tobj = None
                                try:
                                    g = getattr(lib, "get_type_by_name", None)
                                    if callable(g):
                                        tobj = g(nm)
                                except Exception:
                                    tobj = None
                                add_type_entry(nm, tobj)
                            except Exception:
                                continue
                except Exception:
                    pass
        except Exception as e:
            bn.log_error(f"Error listing local types: {e}")
        return results[offset : offset + limit]

    def search_local_types(self, query: str, offset: int = 0, limit: int = 100, include_libraries: bool = False) -> List[Dict[str, Any]]:
        """Search local/view types whose name or declaration contains the substring.

        Returns entries with {name, kind, type_class, decl}.
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
        if not query:
            return []
        ql = str(query).lower()
        # Only local types by default (fast). Optionally include libraries.
        all_types = self.list_local_types(0, 1_000_000, include_libraries=include_libraries)
        matches: List[Dict[str, Any]] = []
        for t in all_types:
            try:
                name = t.get("name") or ""
                decl = t.get("decl") or ""
                if (ql in str(name).lower()) or (ql in str(decl).lower()):
                    matches.append(t)
            except Exception:
                continue
        if isinstance(limit, int) and limit < 0:
            return matches[offset:]
        return matches[offset : offset + limit]

    def get_type_info(self, name: str) -> Dict[str, Any]:
        """Resolve a type by name and return detailed information.

        Returns a dictionary with:
        - name: type name
        - kind: struct/union/class/enum/typedef/... (best-effort)
        - decl: declaration string
        - members: for struct/union [{name, type, offset}]
        - enum_members: for enums [{name, value}]
        - underlying: for typedefs, best-effort underlying declaration
        - source: local | library | unknown
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        type_name = str(name)
        tobj = None
        source = "unknown"

        # 1) Try view local resolution first
        try:
            if hasattr(self._current_view, "get_type_by_name"):
                t = self._current_view.get_type_by_name(type_name)
                if t is not None:
                    tobj = t
                    source = "local"
        except Exception:
            pass

        # 2) Fall back to platform type libraries
        if tobj is None:
            try:
                plat = getattr(self._current_view, "platform", None)
                libs = list(getattr(plat, "type_libraries", []) or []) if plat else []
                for lib in libs:
                    get_t = getattr(lib, "get_type_by_name", None)
                    if not callable(get_t):
                        continue
                    try:
                        # Try with QualifiedName if available
                        try:
                            t = get_t(bn.QualifiedName(type_name))
                        except Exception:
                            t = get_t(type_name)
                    except Exception:
                        t = None
                    if t is not None:
                        tobj = t
                        source = "library"
                        break
            except Exception:
                pass

        # Prepare defaults
        kind = "unknown"
        decl = None
        members: List[Dict[str, Any]] = []
        enum_members: List[Dict[str, Any]] = []
        underlying = None

        # Extract details from type object
        if tobj is not None:
            try:
                decl = str(tobj)
            except Exception:
                try:
                    decl = str(getattr(tobj, "type", None))
                except Exception:
                    decl = None

            tc = getattr(tobj, "type_class", None)
            if tc == TypeClass.StructureTypeClass:
                # structure variant
                try:
                    v = getattr(tobj, "type", None)
                    if v == StructureVariant.UnionStructureType:
                        kind = "union"
                    elif v == StructureVariant.ClassStructureType:
                        kind = "class"
                    else:
                        kind = "struct"
                except Exception:
                    kind = "struct"

                # collect members
                try:
                    for m in getattr(tobj, "members", getattr(getattr(tobj, "structure", None), "members", [])):
                        try:
                            members.append({
                                "name": getattr(m, "name", None),
                                "type": str(getattr(m, "type", "")) if hasattr(m, "type") else None,
                                "offset": int(getattr(m, "offset", 0)) if hasattr(m, "offset") else None,
                            })
                        except Exception:
                            continue
                except Exception:
                    pass

            elif tc == TypeClass.EnumerationTypeClass:
                kind = "enum"
                try:
                    for em in getattr(tobj, "members", []):
                        try:
                            enum_members.append({
                                "name": getattr(em, "name", None),
                                "value": getattr(em, "value", None),
                            })
                        except Exception:
                            continue
                except Exception:
                    pass

            elif tc == TypeClass.NamedTypeReferenceClass:
                kind = "typedef"
                # best-effort underlying from decl text
                try:
                    dlow = (decl or "").lower()
                    if dlow:
                        if dlow.startswith("struct ") or " struct " in dlow:
                            underlying = "struct"
                        elif dlow.startswith("union ") or " union " in dlow:
                            underlying = "union"
                        elif dlow.startswith("enum ") or " enum " in dlow:
                            underlying = "enum"
                except Exception:
                    pass

            elif tc == TypeClass.IntegerTypeClass:
                kind = "int"
            elif tc == TypeClass.FloatTypeClass:
                kind = "float"
            elif tc == TypeClass.BoolTypeClass:
                kind = "bool"
            elif tc == TypeClass.VoidTypeClass:
                kind = "void"
            elif tc == TypeClass.PointerTypeClass:
                kind = "pointer"
            elif tc == TypeClass.ArrayTypeClass:
                kind = "array"
            elif tc == TypeClass.FunctionTypeClass:
                kind = "function"

            # Infer kind from decl if still unknown
            if kind == "unknown" and decl:
                try:
                    dl = decl.lower()
                    if dl.startswith("struct ") or " struct " in dl:
                        kind = "struct"
                    elif dl.startswith("union ") or " union " in dl:
                        kind = "union"
                    elif dl.startswith("enum ") or " enum " in dl:
                        kind = "enum"
                except Exception:
                    pass

        return {
            "name": type_name,
            "kind": kind,
            "decl": decl,
            "members": members if members else None,
            "enum_members": enum_members if enum_members else None,
            "underlying": underlying,
            "source": source,
        }

    def get_strings(self, offset: int = 0, limit: int = 100) -> List[Dict[str, Any]]:
        """Get list of strings in the current binary view with pagination.

        Returns a list of dictionaries containing:
        - address: start address of the string (hex)
        - length: length in bytes (int if available)
        - type: Binary Ninja string type (str if available)
        - value: best-effort decoded and escaped string value
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        results: List[Dict[str, Any]] = []

        try:
            # Prefer modern API if available
            strings_iter = None
            if hasattr(self._current_view, "get_strings"):
                try:
                    strings_iter = self._current_view.get_strings()
                except TypeError:
                    strings_iter = None

            if strings_iter is None and hasattr(self._current_view, "strings"):
                try:
                    strings_iter = list(self._current_view.strings)
                except Exception:
                    strings_iter = []

            if strings_iter is None:
                strings_iter = []

            for s in strings_iter:
                try:
                    addr = None
                    length = None
                    stype = None
                    value = None

                    # Common attributes on StringReference
                    addr = getattr(s, "start", getattr(s, "address", None))
                    length = getattr(s, "length", None)
                    stype = getattr(s, "type", None)
                    if stype is not None:
                        try:
                            stype = str(stype)
                        except Exception:
                            stype = str(stype)

                    value = getattr(s, "value", None)

                    # Best-effort read/decode if value is not present
                    if value is None and addr is not None and length is not None:
                        try:
                            raw = self._current_view.read(addr, length)
                            # Stop at first null byte if present
                            nul = raw.find(b"\x00")
                            if nul != -1:
                                raw = raw[:nul]
                            try:
                                value = raw.decode("utf-8", errors="ignore")
                            except Exception:
                                value = raw.decode("latin-1", errors="ignore")
                        except Exception:
                            value = None

                    # Ensure value is a string and escape non-ASCII
                    if value is None:
                        value = ""
                    value = escape_non_ascii(str(value))

                    results.append(
                        {
                            "address": hex(addr) if isinstance(addr, int) else (str(addr) if addr is not None else None),
                            "length": int(length) if isinstance(length, (int,)) else (None if length is None else int(length)),
                            "type": stype,
                            "value": value,
                        }
                    )
                except Exception as e:
                    # Keep collecting even if one entry fails
                    bn.log_debug(f"Error processing string entry: {e}")
                    continue

            return results[offset : offset + limit]
        except Exception as e:
            bn.log_error(f"Error getting strings: {e}")
            return []

    def set_comment(self, address: int, comment: str) -> bool:
        """Set a comment at a specific address.

        Args:
            address: The address to set the comment at
            comment: The comment text to set

        Returns:
            True if the comment was set successfully, False otherwise
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        try:
            if not self._current_view.is_valid_offset(address):
                bn.log_error(f"Invalid address for comment: {hex(address)}")
                return False

            self._current_view.set_comment_at(address, comment)
            bn.log_debug(f"Set comment at {hex(address)}")
            return True
        except Exception as e:
            bn.log_error(f"Failed to set comment: {e}")
            return False

    def set_function_comment(self, identifier: Union[str, int], comment: str) -> bool:
        """Set a comment for a function.

        Args:
            identifier: Function name or address
            comment: The comment text to set

        Returns:
            True if the comment was set successfully, False otherwise
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        try:
            func = self.get_function_by_name_or_address(identifier)
            if not func:
                bn.log_error(f"Function not found: {identifier}")
                return False

            self._current_view.set_comment_at(func.start, comment)
            bn.log_debug(f"Set comment for function {func.name} at {hex(func.start)}")
            return True
        except Exception as e:
            bn.log_error(f"Failed to set function comment: {e}")
            return False

    def get_comment(self, address: int) -> Optional[str]:
        """Get the comment at a specific address.

        Args:
            address: The address to get the comment from

        Returns:
            The comment text if found, None otherwise
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        try:
            if not self._current_view.is_valid_offset(address):
                bn.log_error(f"Invalid address for comment: {hex(address)}")
                return None

            comment = self._current_view.get_comment_at(address)
            return comment if comment else None
        except Exception as e:
            bn.log_error(f"Failed to get comment: {e}")
            return None

    def get_function_comment(self, identifier: Union[str, int]) -> Optional[str]:
        """Get the comment for a function.

        Args:
            identifier: Function name or address

        Returns:
            The comment text if found, None otherwise
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        try:
            func = self.get_function_by_name_or_address(identifier)
            if not func:
                bn.log_error(f"Function not found: {identifier}")
                return None

            comment = self._current_view.get_comment_at(func.start)
            return comment if comment else None
        except rc.AmbiguousError:
            # An ambiguous name is an error (409 with candidates), never "no comment found".
            raise
        except Exception as e:
            bn.log_error(f"Failed to get function comment: {e}")
            return None

    def delete_comment(self, address: int) -> bool:
        """Delete a comment at a specific address"""
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        try:
            if self._current_view.is_valid_offset(address):
                self._current_view.set_comment_at(address, None)
                return True
        except Exception as e:
            bn.log_error(f"Failed to delete comment: {e}")
        return False

    def delete_function_comment(self, identifier: Union[str, int]) -> bool:
        """Delete a comment for a function"""
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        try:
            func = self.get_function_by_name_or_address(identifier)
            if not func:
                return False
                
            func.comment = None
            return True
        except Exception as e:
            bn.log_error(f"Failed to delete function comment: {e}")
        return False
        


    def get_assembly_function(self, identifier: Union[str, int]) -> Optional[str]:
        """Get the assembly representation of a function with practical annotations.

        Args:
            identifier: Function name or address

        Returns:
            Assembly code as string, or None if the function cannot be found
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        try:
            func = self.get_function_by_name_or_address(identifier)
            if not func:
                bn.log_error(f"Function not found: {identifier}")
                return None
                
            bn.log_debug(f"Found function: {func.name} at {hex(func.start)}")
            
            # Stack-variable names are not added to the listing (upstream left this open: var.storage did not give
            # the correct stack offset), so the map stays empty.
            var_map = {}
            assembly_blocks = {}
            
            if not hasattr(func, "basic_blocks") or not func.basic_blocks:
                bn.log_error(f"Function {func.name} has no basic blocks")
                # Try alternate approach with linear disassembly
                start_addr = func.start
                try:
                    func_length = func.total_bytes
                    if func_length <= 0:
                        func_length = 1024  # Use a reasonable default if length not available
                except:
                    func_length = 1024  # Use a reasonable default if error
                    
                try:
                    # Create one big block for the entire function
                    block_lines = []
                    current_addr = start_addr
                    end_addr = start_addr + func_length
                    
                    while current_addr < end_addr:
                        try:
                            # Get instruction length
                            instr_len = self._current_view.get_instruction_length(current_addr)
                            if instr_len <= 0:
                                instr_len = 4  # Default to a reasonable instruction length
                                
                            # Get disassembly for this instruction
                            line = self._get_instruction_with_annotations(current_addr, instr_len, var_map)
                            if line:
                                block_lines.append(line)
                                
                            current_addr += instr_len
                        except Exception as e:
                            bn.log_error(f"Error processing address {hex(current_addr)}: {str(e)}")
                            block_lines.append(f"# Error at {hex(current_addr)}: {str(e)}")
                            current_addr += 1  # Skip to next byte
                    
                    assembly_blocks[start_addr] = [f"# Block at {hex(start_addr)}"] + block_lines + [""]
                    
                except Exception as e:
                    bn.log_error(f"Linear disassembly failed: {str(e)}")
                    return None
            else:
                for i, block in enumerate(func.basic_blocks):
                    try:
                        block_lines = []
                        
                        # Process each address in the block
                        addr = block.start
                        while addr < block.end:
                            try:
                                instr_len = self._current_view.get_instruction_length(addr)
                                if instr_len <= 0:
                                    instr_len = 4  # Default to a reasonable instruction length
                                
                                # Get disassembly for this instruction
                                line = self._get_instruction_with_annotations(addr, instr_len, var_map)
                                if line:
                                    block_lines.append(line)
                                    
                                addr += instr_len
                            except Exception as e:
                                bn.log_error(f"Error processing address {hex(addr)}: {str(e)}")
                                block_lines.append(f"# Error at {hex(addr)}: {str(e)}")
                                addr += 1  # Skip to next byte
                        
                        # Store block with its starting address as key
                        assembly_blocks[block.start] = [f"# Block {i+1} at {hex(block.start)}"] + block_lines + [""]
                        
                    except Exception as e:
                        bn.log_error(f"Error processing block {i+1} at {hex(block.start)}: {str(e)}")
                        assembly_blocks[block.start] = [f"# Error processing block {i+1} at {hex(block.start)}: {str(e)}", ""]
            
            # Sort blocks by address and concatenate them
            sorted_blocks = []
            for addr in sorted(assembly_blocks.keys()):
                sorted_blocks.extend(assembly_blocks[addr])
            
            return "\n".join(sorted_blocks)
        except Exception as e:
            bn.log_error(f"Error getting assembly for function {identifier}: {str(e)}")
            import traceback
            bn.log_error(traceback.format_exc())
            return None

    def _get_instruction_with_annotations(self, addr: int, instr_len: int, var_map: Dict[int, str]) -> Optional[str]:
        """Get a single instruction with practical annotations.
        
        Args:
            addr: Address of the instruction
            instr_len: Length of the instruction
            var_map: Dictionary mapping offsets to variable names
            
        Returns:
            Formatted instruction string with annotations
        """
        if not self._current_view:
            return None
            
        try:
            # Get raw bytes for fallback
            try:
                raw_bytes = self._current_view.read(addr, instr_len)
                hex_bytes = ' '.join(f'{b:02x}' for b in raw_bytes)
            except:
                hex_bytes = "??"
                
            # Get basic disassembly
            disasm_text = ""
            try:
                if hasattr(self._current_view, "get_disassembly"):
                    disasm = self._current_view.get_disassembly(addr)
                    if disasm:
                        disasm_text = disasm
            except:
                disasm_text = hex_bytes + " ; [Raw bytes]"
                
            if not disasm_text:
                disasm_text = hex_bytes + " ; [Raw bytes]"
                
            # Check if this is a call instruction and try to get target function name
            if "call" in disasm_text.lower():
                try:
                    # Extract the address from the call instruction
                    import re
                    addr_pattern = r'0x[0-9a-fA-F]+'
                    match = re.search(addr_pattern, disasm_text)
                    if match:
                        call_addr_str = match.group(0)
                        call_addr = int(call_addr_str, 16)
                        
                        # Look up the target function name
                        sym = self._current_view.get_symbol_at(call_addr)
                        if sym and hasattr(sym, "name"):
                            # Replace the address with the function name
                            disasm_text = disasm_text.replace(call_addr_str, sym.name)
                except:
                    pass
                    
            # Try to annotate memory references with variable names
            try:
                # Look for memory references like [reg+offset]
                import re
                mem_ref_pattern = r'\[([^\]]+)\]'
                mem_refs = re.findall(mem_ref_pattern, disasm_text)
                
                # For each memory reference, check if it's a known variable
                for mem_ref in mem_refs:
                    # Parse for ebp relative references
                    offset_pattern = r'(ebp|rbp)(([+-]0x[0-9a-fA-F]+)|([+-]\d+))'
                    offset_match = re.search(offset_pattern, mem_ref)
                    if offset_match:
                        # Extract the offset
                        offset_str = offset_match.group(2)
                        
                        # Convert offset to integer
                        try:
                            offset = int(offset_str, 16) if offset_str.startswith('0x') or offset_str.startswith('-0x') else int(offset_str)      
                            
                            # Try to find variable name
                            var_name = var_map.get(offset)
                            
                            # If found, add it to the memory reference
                            if var_name:
                                old_ref = f"[{mem_ref}]"
                                new_ref = f"[{mem_ref} {{{var_name}}}]"
                                disasm_text = disasm_text.replace(old_ref, new_ref)
                        except:
                            pass
            except:
                pass
                
            # Get comment if any
            comment = None
            try:
                comment = self._current_view.get_comment_at(addr)
            except:
                pass
                
            # Format the final line
            addr_str = f"{addr:08x}"
            # Include hex bytes column padded for readability
            bytes_col = f"{hex_bytes}".ljust(16)
            line = f"{addr_str}  {bytes_col} {disasm_text}"
            
            # Add comment at the end if any
            if comment:
                line += f"  ; {comment}"
                
            return line
        except Exception as e:
            bn.log_error(f"Error annotating instruction at {hex(addr)}: {str(e)}")
            return f"{addr:08x}  {hex_bytes} ; [Error: {str(e)}]"
            
    def get_functions_containing_address(self, address: int) -> list:
        """Get functions containing a specific address.
        
        Args:
            address: The instruction address to find containing functions for
            
        Returns:
            List of function names containing the address
        """
        if not self.current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            functions = list(self.current_view.get_functions_containing(address))
            return [func.name for func in functions]
        except Exception as e:
            bn.log_error(f"Error getting functions containing address {hex(address)}: {e}")
            return []

    def get_entry_points(self) -> List[Dict[str, Any]]:
        """Return entry point(s) for the current binary view.

        Primarily uses `bv.entry_point`. Also includes common startup symbols like
        `_start` when resolvable.
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        bv = self._current_view
        results: List[Dict[str, Any]] = []

        def _append(addr: int):
            try:
                if addr is None:
                    return
                name = None
                try:
                    sym = bv.get_symbol_at(addr)
                    if sym and getattr(sym, "name", None):
                        name = sym.name
                except Exception:
                    pass
                if name is None:
                    try:
                        func = bv.get_function_at(addr)
                        if func and getattr(func, "name", None):
                            name = func.name
                    except Exception:
                        pass
                results.append({
                    "address": hex(int(addr)),
                    "name": name,
                })
            except Exception:
                pass

        # Primary entry point
        try:
            ep = getattr(bv, "entry_point", None)
            if isinstance(ep, int) and ep >= 0:
                _append(ep)
        except Exception:
            pass

        # Common startup symbol fallback
        for sname in ("_start", "entry", "start", "WinMain", "mainCRTStartup"):
            try:
                sym = bv.get_symbol_by_name(sname) if hasattr(bv, "get_symbol_by_name") else None
                if sym and hasattr(sym, "address"):
                    addr = int(sym.address)
                    if not any(r.get("address") == hex(addr) for r in results):
                        _append(addr)
            except Exception:
                continue

        return results
            
    # Removed: get_function_code_references() in favor of address-based get_xrefs_to_* helpers
            
    def get_user_defined_type(self, type_name: str) -> Optional[Dict[str, Any]]:
        """Get the definition of a user-defined type (struct, enum, etc.)
        
        Args:
            type_name: Name of the user-defined type to retrieve
            
        Returns:
            Dictionary with type information and definition, or None if not found
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
            
        try:
            # Check if we have a user type container
            if not hasattr(self._current_view, "user_type_container") or not self._current_view.user_type_container:
                bn.log_debug("No user type container available")
                return None
                
            # Search for the requested type by name
            found_type = None
            found_type_id = None
            
            for type_id in self._current_view.user_type_container.types.keys():
                current_type = self._current_view.user_type_container.types[type_id]
                type_name_from_container = current_type[0]
                
                if type_name_from_container == type_name:
                    found_type = current_type
                    found_type_id = type_id
                    break
                    
            if not found_type or not found_type_id:
                bn.log_debug(f"Type not found: {type_name}")
                return None
                
            # Determine the type category (struct, enum, etc.)
            type_category = "unknown"
            type_object = found_type[1]
            if type_object.type_class == TypeClass.EnumerationTypeClass:
                type_category = "enum"
            elif type_object.type_class == TypeClass.StructureTypeClass:
                if type_object.type == StructureVariant.StructStructureType:
                    type_category = "struct"
                elif type_object.type == StructureVariant.UnionStructureType:
                    type_category = "union"
                elif type_object.type == StructureVariant.ClassStructureType:
                    type_category = "class"
            elif type_object.type_class == TypeClass.NamedTypeReferenceClass:
                type_category = "typedef"

            # Generate the C++ style definition
            definition_lines = []
            
            try:
                if type_category == "struct" or type_category == "class" or type_category == "union":
                    definition_lines.append(f"{type_category} {type_name} {{")
                    for member in type_object.members:
                        if hasattr(member, "name") and hasattr(member, "type"):
                            definition_lines.append(f"    {member.type} {member.name};")
                    definition_lines.append("};")
                elif type_category == "enum":
                    definition_lines.append(f"enum {type_name} {{")
                    for member in type_object.members:
                        if hasattr(member, "name") and hasattr(member, "value"):
                            definition_lines.append(f"    {member.name} = {member.value},")
                    definition_lines.append("};")
                elif type_category == "typedef":
                    str_type_object = str(type_object)
                    definition_lines.append(f"typedef {str_type_object};")
            except Exception as e:
                bn.log_error(f"Error getting type lines: {e}")

            # Construct the final definition string
            definition = "\n".join(definition_lines)
            
            return {
                "name": type_name,
                "type": type_category,
                "definition": definition
            }
        except Exception as e:
            bn.log_error(f"Error getting user-defined type {type_name}: {e}")
            return None

    def get_xrefs_to_address(self, address: Union[int, str]) -> Dict[str, Any]:
        """Get all cross references (code and data) to a given address.

        Args:
            address: Address as int, hex string (e.g., "0x401000"), or decimal string

        Returns:
            Dictionary with address, code_references, and data_references lists
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        # Normalize address to int
        try:
            if isinstance(address, str):
                addr = int(address, 16) if address.startswith("0x") else int(address)
            else:
                addr = int(address)
        except (TypeError, ValueError):
            raise ValueError("Invalid address format; use hex (0x...) or decimal")

        result: Dict[str, Any] = {
            "address": hex(addr),
            "code_references": [],
            "data_references": [],
        }

        # Code references
        try:
            if hasattr(self._current_view, "get_code_refs"):
                for ref in list(self._current_view.get_code_refs(addr)):
                    try:
                        fn_name = ref.function.name if getattr(ref, "function", None) else None
                        entry = {"function": fn_name, "address": hex(ref.address)}

                        # Heuristic: only attach a following call if the referenced data
                        # is carried in a parameter register up to that call (likely passed as an arg)
                        try:
                            func = ref.function if getattr(ref, "function", None) else self._current_view.get_function_at(ref.address)
                            if func is not None:
                                import re as _re
                                # identify destination register at xref instruction
                                def _canon_reg(r: str) -> str:
                                    r = (r or "").strip().lower()
                                    mp = {
                                        'rcx':'rcx','ecx':'rcx','cx':'rcx','cl':'rcx','ch':'rcx',
                                        'rdx':'rdx','edx':'rdx','dx':'rdx','dl':'rdx','dh':'rdx',
                                        'r8':'r8','r8d':'r8','r8w':'r8','r8b':'r8',
                                        'r9':'r9','r9d':'r9','r9w':'r9','r9b':'r9',
                                        'rdi':'rdi','edi':'rdi','di':'rdi','dil':'rdi',
                                        'rsi':'rsi','esi':'rsi','si':'rsi','sil':'rsi',
                                    }
                                    return mp.get(r, r)
                                def _first_op_reg(d: str) -> str:
                                    try:
                                        parts = d.strip().split(None, 1)
                                        if len(parts) < 2:
                                            return ""
                                        ops = parts[1].split(';',1)[0]
                                        first = ops.split(',',1)[0].strip()
                                        if '[' in first:
                                            return ""
                                        for kw in ("byte","word","dword","qword","ptr"):
                                            if first.startswith(kw):
                                                first = first[len(kw):].strip()
                                        return first.split()[0]
                                    except Exception:
                                        return ""
                                try:
                                    xdis = self._current_view.get_disassembly(ref.address) or ""
                                except Exception:
                                    xdis = ""
                                dest = _canon_reg(_first_op_reg(xdis))
                                arg_regs = {"rcx","rdx","r8","r9","rdi","rsi"}
                                if dest in arg_regs:
                                    steps = 16
                                    curr = ref.address
                                    overwritten = False
                                    while steps > 0 and curr < getattr(func, 'highest_address', curr + 1024):
                                        ilen = self._current_view.get_instruction_length(curr) or 1
                                        try:
                                            dis = self._current_view.get_disassembly(curr) or ""
                                        except Exception:
                                            dis = ""
                                        # detect clobber of the arg register
                                        if curr != ref.address and _canon_reg(_first_op_reg(dis)) == dest:
                                            overwritten = True
                                        if ("call" in dis.lower()) and not overwritten:
                                            entry["following_call_address"] = hex(curr)
                                            m = _re.search(r"0x[0-9a-fA-F]+", dis)
                                            tgt = None
                                            if m:
                                                try:
                                                    tgt = int(m.group(0), 16)
                                                except Exception:
                                                    tgt = None
                                            if tgt is not None:
                                                sym = self._current_view.get_symbol_at(tgt)
                                                if sym and hasattr(sym,'name'):
                                                    entry["following_call_target"] = sym.name
                                                else:
                                                    tfn = self._current_view.get_function_at(tgt)
                                                    entry["following_call_target"] = tfn.name if (tfn and hasattr(tfn,'name')) else hex(tgt)
                                            break
                                        curr += max(1, ilen)
                                        steps -= 1
                        except Exception:
                            pass

                        result["code_references"].append(entry)
                    except Exception:
                        continue
        except Exception as e:
            bn.log_error(f"Error getting code references to {hex(addr)}: {e}")

        # Data references
        try:
            if hasattr(self._current_view, "get_data_refs"):
                for ref_addr in list(self._current_view.get_data_refs(addr)):
                    try:
                        fn = self._current_view.get_function_at(ref_addr)
                        fn_name = fn.name if fn else None
                        result["data_references"].append(
                            {"function": fn_name, "address": hex(ref_addr)}
                        )
                    except Exception:
                        continue
        except Exception as e:
            bn.log_error(f"Error getting data references to {hex(addr)}: {e}")

        return result

    # ---- get_xrefs_* stability helpers (indexed, no whole-binary HLIL scan) ----

    def _xref_is_large_binary(self) -> bool:
        """True when the view has too many functions for a whole-binary HLIL
        textual scan (which would hang). len(bv.functions) is O(1): FunctionList
        caches the count, so this never materialises HLIL."""
        try:
            return len(self._current_view.functions) > _XREF_SCAN_FUNC_THRESHOLD
        except Exception:
            # If the count can't be read, treat as small (preserve original
            # textual behaviour) rather than silently skipping the scan.
            return False

    def _native_code_refs(self, name: str, max_items: int = _XREF_NATIVE_MAX) -> List[Dict[str, Any]]:
        """Indexed code cross-references to a type via BN get_code_refs_for_type.
        Returns [{function, address, text, via}]. Generator yields ReferenceSource
        objects whose attribute is `.function` (NOT `.func`)."""
        out: List[Dict[str, Any]] = []
        bv = self._current_view
        if not bv or not name:
            return out
        try:
            try:
                gen = bv.get_code_refs_for_type(name, max_items=max_items)
            except TypeError:
                gen = bv.get_code_refs_for_type(name)  # older builds: no max_items kw
        except Exception:
            return out
        try:
            for ref in gen:
                try:
                    fn = getattr(ref, "function", None)
                    addr = int(getattr(ref, "address", 0))
                    try:
                        text = bv.get_disassembly(addr, getattr(ref, "arch", None))
                    except Exception:
                        text = None
                    out.append({
                        "function": fn.name if fn else None,
                        "address": hex(addr),
                        "text": text,
                        "via": "type-index",
                    })
                    if len(out) >= max_items:
                        break
                except Exception:
                    continue
        except Exception:
            pass
        return out

    def _native_field_code_refs(self, name: str, offset: int, max_items: int = _XREF_NATIVE_MAX) -> List[Dict[str, Any]]:
        """Indexed code cross-references to a specific type field (struct/union
        member) via BN get_code_refs_for_type_field. Returns
        [{function, address, text, via}]. Generator yields TypeFieldReference whose
        function attribute is `.func` (NOT `.function`)."""
        out: List[Dict[str, Any]] = []
        bv = self._current_view
        if not bv or not name or offset is None:
            return out
        try:
            try:
                gen = bv.get_code_refs_for_type_field(name, int(offset), max_items=max_items)
            except TypeError:
                gen = bv.get_code_refs_for_type_field(name, int(offset))
        except Exception:
            return out
        try:
            for ref in gen:
                try:
                    fn = getattr(ref, "func", None)
                    addr = int(getattr(ref, "address", 0))
                    try:
                        text = bv.get_disassembly(addr, getattr(ref, "arch", None))
                    except Exception:
                        text = None
                    out.append({
                        "function": fn.name if fn else None,
                        "address": hex(addr),
                        "text": text,
                        "via": "type-field-index",
                    })
                    if len(out) >= max_items:
                        break
                except Exception:
                    continue
        except Exception:
            pass
        return out

    def _native_data_refs(self, name: str, max_items: int = _XREF_NATIVE_MAX) -> List[Dict[str, Any]]:
        """Indexed data instances of a type via BN get_data_refs_for_type (which
        yields virtual addresses). Returns [{address, type, name, via}]."""
        out: List[Dict[str, Any]] = []
        bv = self._current_view
        if not bv or not name:
            return out
        try:
            try:
                gen = bv.get_data_refs_for_type(name, max_items=max_items)
            except TypeError:
                gen = bv.get_data_refs_for_type(name)
        except Exception:
            return out
        try:
            for addr in gen:
                try:
                    a = int(addr)
                    try:
                        t = bv.get_type_at(a)
                    except Exception:
                        t = None
                    try:
                        sym = bv.get_symbol_at(a)
                    except Exception:
                        sym = None
                    out.append({
                        "address": hex(a),
                        "type": str(t) if t is not None else None,
                        "name": sym.name if sym else None,
                        "via": "type-index",
                    })
                    if len(out) >= max_items:
                        break
                except Exception:
                    continue
        except Exception:
            pass
        return out

    def get_xrefs_to_field(self, struct_name: str, field_name: str) -> List[Dict[str, Any]]:
        """Get all cross references to a named struct field (member).

        This uses a best-effort heuristic:
        - Scans HLIL for occurrences of the field name (e.g., ".field" or "->field")
        - If a global instance of the struct is found, computes the field's absolute
          address (base + offset) and includes code refs to that address
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        struct_name = str(struct_name).strip()
        field_name = str(field_name).strip()
        results: List[Dict[str, Any]] = []

        # Try to resolve struct member offset
        member_offset = None
        try:
            if hasattr(self._current_view, "types") and self._current_view.types:
                for t in self._current_view.types.values():
                    try:
                        if getattr(t, "name", None) == struct_name and hasattr(t, "structure") and t.structure:
                            for m in getattr(t, "members", getattr(t.structure, "members", [])):
                                if getattr(m, "name", None) == field_name and hasattr(m, "offset"):
                                    member_offset = int(m.offset)
                                    break
                            if member_offset is not None:
                                break
                    except Exception:
                        continue
        except Exception:
            pass

        # Large-binary fast path: BN's indexed field-xref API (no whole-binary
        # HLIL scan, which would hang). Return immediately on large binaries.
        if self._xref_is_large_binary():
            if member_offset is not None:
                for r in self._native_field_code_refs(struct_name, member_offset):
                    results.append({
                        "kind": "type-field-index",
                        "function": r.get("function"),
                        "address": r.get("address"),
                        "text": r.get("text"),
                    })
            for r in self._native_code_refs(struct_name):
                results.append({
                    "kind": "type-index",
                    "function": r.get("function"),
                    "address": r.get("address"),
                    "text": r.get("text"),
                })
            return results

        # HLIL scan for textual member access
        import re
        pattern = re.compile(rf"(\.|->)\s*{re.escape(field_name)}(\b|\W)")
        for func in self._current_view.functions:
            if len(results) >= _XREF_SCAN_MAX_MATCHES:
                break
            try:
                if not hasattr(func, "hlil") or not func.hlil:
                    continue
                for ins in func.hlil.instructions:
                    try:
                        text = str(ins)
                        if pattern.search(text):
                            results.append({
                                "kind": "hlil-match",
                                "function": func.name,
                                "address": hex(getattr(ins, "address", func.start)),
                                "text": text
                            })
                    except Exception:
                        continue
            except Exception:
                continue

        # If we know the member offset, try to find global instances and code-refs
        if member_offset is not None:
            try:
                for var_addr in list(self._current_view.data_vars):
                    try:
                        t = None
                        if hasattr(self._current_view, "get_type_at"):
                            t = self._current_view.get_type_at(var_addr)
                        t_str = str(t) if t is not None else ""
                        # crude match for exact or pointer to struct
                        if t_str == struct_name or t_str.endswith(f"* {struct_name}") or struct_name in t_str:
                            field_addr = var_addr + member_offset
                            # code refs to this absolute address
                            try:
                                for ref in list(self._current_view.get_code_refs(field_addr)):
                                    fn_name = ref.function.name if getattr(ref, "function", None) else None
                                    results.append({
                                        "kind": "global-field-ref",
                                        "function": fn_name,
                                        "address": hex(ref.address),
                                        "field_address": hex(field_addr),
                                    })
                            except Exception:
                                pass
                    except Exception:
                        continue
            except Exception:
                pass

        return results

    def get_xrefs_to_type(self, type_name: str) -> Dict[str, Any]:
        """Get cross references/usages related to a struct/type name.

        Best-effort heuristics:
        - Finds global data variables whose type string mentions the type name; includes code refs to those globals
        - Scans HLIL text for instructions mentioning the type (casts/annotations)
        - Marks functions whose signature mentions the type
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        type_name = str(type_name).strip()
        tnl = type_name.lower()

        result: Dict[str, Any] = {
            "type": type_name,
            "data_instances": [],   # [{address, type, name?}]
            "data_code_references": [],  # [{function, address, target}]
            "code_references": [],  # HLIL matches [{function, address, text}]
            "functions_with_type": [],  # function names
        }

        # Large-binary fast path: indexed type-xref APIs only (the data_var +
        # whole-binary HLIL scans below hang on large binaries).
        if self._xref_is_large_binary():
            result["data_instances"] = self._native_data_refs(type_name)
            result["code_references"] = self._native_code_refs(type_name)
            result["scan_skipped_large_binary"] = True
            return result

        # 1) Global data variables whose type matches the type name
        try:
            for var_addr in list(self._current_view.data_vars):
                try:
                    t = None
                    if hasattr(self._current_view, "get_type_at"):
                        t = self._current_view.get_type_at(var_addr)
                    t_str = str(t) if t is not None else ""
                    if t_str and tnl in t_str.lower():
                        sym = self._current_view.get_symbol_at(var_addr)
                        result["data_instances"].append(
                            {
                                "address": hex(var_addr),
                                "type": t_str,
                                "name": sym.name if sym else None,
                            }
                        )
                        # Also add code refs to this global
                        try:
                            if hasattr(self._current_view, "get_code_refs"):
                                for ref in list(self._current_view.get_code_refs(var_addr)):
                                    fn_name = ref.function.name if getattr(ref, "function", None) else None
                                    result["data_code_references"].append(
                                        {
                                            "function": fn_name,
                                            "address": hex(ref.address),
                                            "target": hex(var_addr),
                                        }
                                    )
                        except Exception:
                            pass
                except Exception:
                    continue
        except Exception:
            pass

        # 2) HLIL textual matches for the type (casts/annotations)
        try:
            import re
            # Look for the type name as a word or part of a cast/annotation
            pat = re.compile(re.escape(type_name), re.IGNORECASE)
            for func in self._current_view.functions:
                if len(result["code_references"]) >= _XREF_SCAN_MAX_MATCHES:
                    break
                try:
                    if hasattr(func, "hlil") and func.hlil:
                        for ins in func.hlil.instructions:
                            try:
                                text = str(ins)
                                if pat.search(text):
                                    result["code_references"].append(
                                        {
                                            "function": func.name,
                                            "address": hex(getattr(ins, "address", func.start)),
                                            "text": text,
                                        }
                                    )
                            except Exception:
                                continue
                    # 3) Functions whose signature mentions the type
                    try:
                        sig_text = str(func.type)
                        if sig_text and tnl in sig_text.lower():
                            result["functions_with_type"].append(func.name)
                    except Exception:
                        pass
                except Exception:
                    continue
        except Exception:
            pass

        # Deduplicate function list
        try:
            result["functions_with_type"] = sorted(list(set(result["functions_with_type"])) )
        except Exception:
            pass

        return result

    def get_xrefs_to_enum(self, enum_name: str) -> Dict[str, Any]:
        """Find usages of an enum by matching its member values in code and variables.

        Notes:
        - Enums are values, not addresses; there are no traditional "data references" to enums.
        - This scans for immediate constants equal to enum members and common bitmask checks.
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        enum_name_str = str(enum_name).strip()
        en_lower = enum_name_str.lower()

        result: Dict[str, Any] = {
            "enum": enum_name_str,
            "members": [],  # [{name, value}]
            "usages": [],   # [{function, address, text, member, value}]
        }

        # Locate the enum type and collect members
        enum_type = None
        try:
            for t in self._current_view.types.values():
                try:
                    # Match by exact name or case-insensitive
                    if getattr(t, "type_class", None) == TypeClass.EnumerationTypeClass:
                        tname = getattr(t, "name", None)
                        if tname and tname.lower() == en_lower:
                            enum_type = t
                            break
                except Exception:
                    continue
        except Exception:
            pass

        # If not found by exact name, try substring match
        if enum_type is None:
            try:
                for t in self._current_view.types.values():
                    try:
                        if getattr(t, "type_class", None) == TypeClass.EnumerationTypeClass:
                            tname = getattr(t, "name", "")
                            if tname and en_lower in tname.lower():
                                enum_type = t
                                break
                    except Exception:
                        continue
            except Exception:
                pass

        members: List[Dict[str, Any]] = []
        values: List[int] = []
        if enum_type is not None:
            try:
                for m in getattr(enum_type, "members", []):
                    try:
                        name = getattr(m, "name", None)
                        val = getattr(m, "value", None)
                        if name is not None and isinstance(val, int):
                            members.append({"name": name, "value": val})
                            values.append(val)
                    except Exception:
                        continue
            except Exception:
                pass

        result["members"] = members

        # Large-binary fast path: indexed refs to the enum *type* only. The value
        # scan below walks every HLIL instruction in the binary and hangs on large
        # binaries, so skip it and serve type-level references instead.
        if self._xref_is_large_binary():
            result["type_references"] = self._native_code_refs(enum_name_str)
            result["scan_skipped_large_binary"] = True
            return result

        # Build simple patterns for HLIL text matching of constants (hex)
        import re
        hex_patterns = []
        for v in values:
            hex_patterns.append(re.compile(rf"0x{v:x}\b", re.IGNORECASE))
        # Also a single combined pattern to speed up
        combined_hex = None
        if values:
            combined_hex = re.compile(r"(" + "|".join([rf"0x{v:x}\b" for v in values]) + ")", re.IGNORECASE)

        # Scan functions for matches
        for func in self._current_view.functions:
            if len(result["usages"]) >= _XREF_SCAN_MAX_MATCHES:
                break
            try:
                if hasattr(func, "hlil") and func.hlil:
                    for ins in func.hlil.instructions:
                        try:
                            text = str(ins)
                            matched_val = None
                            if combined_hex is not None:
                                m = combined_hex.search(text)
                                if m:
                                    # parse the matched hex back to int to map member name
                                    try:
                                        matched_val = int(m.group(0), 16)
                                    except Exception:
                                        matched_val = None
                            if matched_val is not None:
                                member_name = None
                                for mem in members:
                                    if mem["value"] == matched_val:
                                        member_name = mem["name"]
                                        break
                                result["usages"].append(
                                    {
                                        "function": func.name,
                                        "address": hex(getattr(ins, "address", func.start)),
                                        "text": text,
                                        "member": member_name,
                                        "value": matched_val,
                                    }
                                )
                        except Exception:
                            continue
            except Exception:
                continue

        return result

    def get_xrefs_to_struct(self, struct_name: str) -> Dict[str, Any]:
        """Get cross references/usages related specifically to a struct name.

        Includes:
        - members: list of struct members with offsets and types
        - data_instances: globals whose type mentions the struct
        - data_code_references: code refs to those globals
        - field_code_references: code refs to addresses of global_instance + member offset
        - code_references: HLIL lines with member access (".field"/"->field")
        - functions_with_type: functions whose signatures mention the struct
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        name = str(struct_name).strip()
        name_l = name.lower()
        # Build candidate names to handle common PE struct aliases
        candidate_names = {name}
        # Remove leading underscore variant
        if name.startswith("_"):
            candidate_names.add(name[1:])
        else:
            candidate_names.add("_" + name)
        # PE-specific heuristics
        nl = name_l
        if "coff" in nl and "header" in nl:
            candidate_names.update({"IMAGE_FILE_HEADER", "_IMAGE_FILE_HEADER"})
        if ("pe64" in nl or "optional_header64" in nl or "optional" in nl) and "header" in nl:
            candidate_names.update({"IMAGE_OPTIONAL_HEADER64", "_IMAGE_OPTIONAL_HEADER64"})
        if ("pe32" in nl or "optional_header32" in nl or ("optional" in nl and "64" not in nl)) and "header" in nl:
            candidate_names.update({"IMAGE_OPTIONAL_HEADER32", "_IMAGE_OPTIONAL_HEADER32"})
        if "dos" in nl and "header" in nl:
            candidate_names.update({"IMAGE_DOS_HEADER", "_IMAGE_DOS_HEADER"})
        candidate_names_l = {c.lower() for c in candidate_names}

        out: Dict[str, Any] = {
            "struct": name,
            "members": [],
            "data_instances": [],
            "data_code_references": [],
            "field_code_references": [],
            "code_references": [],
            "functions_with_type": [],
            "vars_with_type": [],
            "code_references_by_cast": [],
        }

        # Resolve the struct type and members
        members = []
        try:
            for t in self._current_view.types.values():
                try:
                    if getattr(t, "type_class", None) == TypeClass.StructureTypeClass:
                        tname = getattr(t, "name", None)
                        if not tname:
                            continue
                        tl = tname.lower()
                        if tl == name_l or name_l in tl or tl in candidate_names_l:
                            for m in getattr(t, "members", getattr(getattr(t, "structure", None), "members", [])):
                                try:
                                    members.append(
                                        {
                                            "name": getattr(m, "name", None),
                                            "offset": int(getattr(m, "offset", 0))
                                            if hasattr(m, "offset")
                                            else None,
                                            "type": str(getattr(m, "type", ""))
                                            if hasattr(m, "type")
                                            else None,
                                        }
                                    )
                                except Exception:
                                    continue
                            break
                except Exception:
                    continue
        except Exception:
            pass
        out["members"] = members

        # Large-binary fast path: indexed type/field-xref APIs only. Every scan
        # below (data_vars, get_symbols, parent-struct walk, whole-binary HLIL)
        # is O(whole-binary) and hangs on large binaries, so return early.
        if self._xref_is_large_binary():
            out["data_instances"] = self._native_data_refs(name)
            out["data_code_references"] = self._native_code_refs(name)
            for m in members:
                if len(out["field_code_references"]) >= _XREF_SCAN_MAX_MATCHES:
                    out["scan_truncated"] = True
                    break
                off = m.get("offset")
                if off is None:
                    continue
                for r in self._native_field_code_refs(name, off):
                    out["field_code_references"].append({
                        "function": r.get("function"),
                        "address": r.get("address"),
                        "field_address": None,
                        "member": m.get("name"),
                        "text": r.get("text"),
                    })
            out["scan_skipped_large_binary"] = True
            return out

        # Gather globals with this struct in their type string
        global_instances: List[int] = []
        try:
            for var_addr in list(self._current_view.data_vars):
                try:
                    t = None
                    if hasattr(self._current_view, "get_type_at"):
                        t = self._current_view.get_type_at(var_addr)
                    t_str = str(t) if t is not None else ""
                    if t_str:
                        tl = t_str.lower()
                        if name_l in tl or any(cn in tl for cn in candidate_names_l):
                            sym = self._current_view.get_symbol_at(var_addr)
                            out["data_instances"].append(
                                {
                                    "address": hex(var_addr),
                                    "type": t_str,
                                    "name": sym.name if sym else None,
                                }
                            )
                            global_instances.append(var_addr)
                            # Code refs to the variable itself
                        try:
                            if hasattr(self._current_view, "get_code_refs"):
                                for ref in list(self._current_view.get_code_refs(var_addr)):
                                    fn_name = (
                                        ref.function.name
                                        if getattr(ref, "function", None)
                                        else None
                                    )
                                    out["data_code_references"].append(
                                        {
                                            "function": fn_name,
                                            "address": hex(ref.address),
                                            "target": hex(var_addr),
                                        }
                                    )
                        except Exception:
                            pass
                except Exception:
                    continue
        except Exception:
            pass

        # Also gather symbol-based instances whose name mentions the struct alias
        symbol_instances: List[int] = []
        try:
            for sym in list(self._current_view.get_symbols()):
                try:
                    sname = getattr(sym, "name", "") or ""
                    sfull = getattr(sym, "full_name", "") or ""
                    sl = (sname + " " + sfull).lower()
                    if any(cn in sl for cn in candidate_names_l):
                        addr = getattr(sym, "address", None)
                        if isinstance(addr, int):
                            # capture as data instance if not already present
                            out["data_instances"].append(
                                {
                                    "address": hex(addr),
                                    "type": None,
                                    "name": sname,
                                }
                            )
                            symbol_instances.append(addr)
                            # code refs to this symbol
                            try:
                                if hasattr(self._current_view, "get_code_refs"):
                                    for ref in list(self._current_view.get_code_refs(addr)):
                                        fn_name = (
                                            ref.function.name
                                            if getattr(ref, "function", None)
                                            else None
                                        )
                                        out["data_code_references"].append(
                                            {
                                                "function": fn_name,
                                                "address": hex(ref.address),
                                                "target": hex(addr),
                                            }
                                        )
                            except Exception:
                                pass
                except Exception:
                    continue
        except Exception:
            pass

        # Code refs to computed field addresses for each global instance
        if members and (global_instances or symbol_instances):
            try:
                for base in list(set(global_instances + symbol_instances)):
                    for m in members:
                        try:
                            off = m.get("offset")
                            if off is None:
                                continue
                            field_addr = base + int(off)
                            if hasattr(self._current_view, "get_code_refs"):
                                for ref in list(self._current_view.get_code_refs(field_addr)):
                                    fn_name = (
                                        ref.function.name
                                        if getattr(ref, "function", None)
                                        else None
                                    )
                                    out["field_code_references"].append(
                                        {
                                            "function": fn_name,
                                            "address": hex(ref.address),
                                            "field_address": hex(field_addr),
                                            "member": m.get("name"),
                                        }
                                    )
                        except Exception:
                            continue
            except Exception:
                pass

        # If the struct is contained as a field of another struct, try deriving field addresses from parent instances
        try:
            parent_offsets: List[Dict[str, Any]] = []
            for t in self._current_view.types.values():
                try:
                    if getattr(t, "type_class", None) == TypeClass.StructureTypeClass:
                        tname = getattr(t, "name", None)
                        if not tname:
                            continue
                        tl = tname.lower()
                        # scan members for types that mention our struct aliases
                        for mem in getattr(t, "members", getattr(getattr(t, "structure", None), "members", [])):
                            try:
                                mtype = getattr(mem, "type", None)
                                mtype_str = str(mtype) if mtype is not None else ""
                                ml = mtype_str.lower()
                                if ml and (name_l in ml or any(cn in ml for cn in candidate_names_l)):
                                    parent_offsets.append(
                                        {
                                            "parent": tname,
                                            "offset": int(getattr(mem, "offset", 0)) if hasattr(mem, "offset") else None,
                                            "member": getattr(mem, "name", None),
                                        }
                                    )
                            except Exception:
                                continue
                except Exception:
                    continue

            # For each parent type, find instances and compute field address
            for po in parent_offsets:
                poff = po.get("offset")
                if poff is None:
                    continue
                parent_name = po.get("parent")
                try:
                    # scan data variables
                    for var_addr in list(self._current_view.data_vars):
                        try:
                            t = None
                            if hasattr(self._current_view, "get_type_at"):
                                t = self._current_view.get_type_at(var_addr)
                            t_str = str(t) if t is not None else ""
                            if t_str and parent_name and parent_name.lower() in t_str.lower():
                                field_addr = var_addr + poff
                                if hasattr(self._current_view, "get_code_refs"):
                                    for ref in list(self._current_view.get_code_refs(field_addr)):
                                        fn_name = (
                                            ref.function.name
                                            if getattr(ref, "function", None)
                                            else None
                                        )
                                        out["field_code_references"].append(
                                            {
                                                "function": fn_name,
                                                "address": hex(ref.address),
                                                "field_address": hex(field_addr),
                                                "member": po.get("member"),
                                            }
                                        )
                        except Exception:
                            continue
                    # scan symbols with parent type in name
                    for sym in list(self._current_view.get_symbols()):
                        try:
                            sname = getattr(sym, "name", "") or ""
                            sfull = getattr(sym, "full_name", "") or ""
                            sl = (sname + " " + sfull).lower()
                            if parent_name and parent_name.lower() in sl:
                                addr = getattr(sym, "address", None)
                                if isinstance(addr, int):
                                    field_addr = addr + poff
                                    if hasattr(self._current_view, "get_code_refs"):
                                        for ref in list(self._current_view.get_code_refs(field_addr)):
                                            fn_name = (
                                                ref.function.name
                                                if getattr(ref, "function", None)
                                                else None
                                            )
                                            out["field_code_references"].append(
                                                {
                                                    "function": fn_name,
                                                    "address": hex(ref.address),
                                                    "field_address": hex(field_addr),
                                                    "member": po.get("member"),
                                                }
                                            )
                        except Exception:
                            continue
                except Exception:
                    continue
        except Exception:
            pass

        # HLIL matches for member access text
        
        try:
            import re
            patterns = []
            for m in members:
                nm = m.get("name")
                if not nm:
                    continue
                patterns.append(re.compile(rf"(\.|->)\s*{re.escape(str(nm))}(\b|\W)", re.IGNORECASE))

            for func in self._current_view.functions:
                if (len(out["code_references"]) >= _XREF_SCAN_MAX_MATCHES
                        or len(out["code_references_by_cast"]) >= _XREF_SCAN_MAX_MATCHES):
                    break
                try:
                    # Capture variables whose type mentions the struct
                    try:
                        for v in getattr(func, "vars", []):
                            try:
                                vtype = getattr(v, "type", None)
                                vname = getattr(v, "name", None)
                                vtype_str = str(vtype) if vtype is not None else ""
                                if vtype_str and name_l in vtype_str.lower():
                                    out["vars_with_type"].append({
                                        "function": func.name,
                                        "var": vname,
                                        "type": vtype_str,
                                    })
                            except Exception:
                                continue
                    except Exception:
                        pass

                    if hasattr(func, "hlil") and func.hlil:
                        for ins in func.hlil.instructions:
                            try:
                                text = str(ins)
                                if any(p.search(text) for p in patterns):
                                    out["code_references"].append(
                                        {
                                            "function": func.name,
                                            "address": hex(getattr(ins, "address", func.start)),
                                            "text": text,
                                        }
                                    )
                                # Also capture casts/annotations explicitly mentioning the struct name
                                tl = text.lower()
                                if name_l in tl or any(cn in tl for cn in candidate_names_l):
                                    # Heuristic: detect patterns like '(COFF_Header*)' or '(struct COFF_Header*)'
                                    cast_pat = r"\(.*(" + "|".join(re.escape(c) for c in candidate_names) + r").*\)"
                                    if re.search(cast_pat, text, re.IGNORECASE):
                                        out["code_references_by_cast"].append(
                                            {
                                                "function": func.name,
                                                "address": hex(getattr(ins, "address", func.start)),
                                                "text": text,
                                            }
                                        )
                            except Exception:
                                continue
                    # Functions whose signature mentions the struct
                    try:
                        sig_text = str(func.type)
                        if sig_text:
                            sl = sig_text.lower()
                            if name_l in sl or any(cn in sl for cn in candidate_names_l):
                                out["functions_with_type"].append(func.name)
                    except Exception:
                        pass
                except Exception:
                    continue
        except Exception:
            pass

        # Dedup functions list
        try:
            out["functions_with_type"] = sorted(list(set(out["functions_with_type"])) )
        except Exception:
            pass

        return out

    def get_xrefs_to_union(self, union_name: str) -> Dict[str, Any]:
        """Get cross references/usages related to a union type by name.

        Includes:
        - members: list of union members with offsets/types (offsets may be 0/overlapping)
        - data_instances: globals whose type mentions the union
        - data_code_references: code refs to those globals
        - code_references: HLIL lines with member access (".field"/"->field")
        - functions_with_type: functions whose signatures mention the union
        - vars_with_type: function-local variables typed as the union
        - code_references_by_cast: HLIL lines with explicit casts mentioning the union
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")

        name = str(union_name).strip()
        name_l = name.lower()

        out: Dict[str, Any] = {
            "union": name,
            "members": [],
            "data_instances": [],
            "data_code_references": [],
            "code_references": [],
            "functions_with_type": [],
            "vars_with_type": [],
            "code_references_by_cast": [],
        }

        # Resolve union members
        members: List[Dict[str, Any]] = []
        try:
            for t in self._current_view.types.values():
                try:
                    # Union types are presented via StructureTypeClass with UnionStructureType variant
                    if getattr(t, "type_class", None) == TypeClass.StructureTypeClass:
                        tname = getattr(t, "name", None)
                        if not tname:
                            continue
                        tl = tname.lower()
                        if tl == name_l or name_l in tl:
                            # If the BN type exposes a variant, prefer checking for union
                            try:
                                if getattr(t, "type", None) == StructureVariant.UnionStructureType:
                                    pass
                            except Exception:
                                pass
                            for m in getattr(t, "members", getattr(getattr(t, "structure", None), "members", [])):
                                try:
                                    members.append(
                                        {
                                            "name": getattr(m, "name", None),
                                            "offset": int(getattr(m, "offset", 0)) if hasattr(m, "offset") else None,
                                            "type": str(getattr(m, "type", "")) if hasattr(m, "type") else None,
                                        }
                                    )
                                except Exception:
                                    continue
                            break
                except Exception:
                    continue
        except Exception:
            pass
        out["members"] = members

        # Large-binary fast path: indexed type/field-xref APIs only (the data_var
        # + whole-binary HLIL scans below hang on large binaries).
        if self._xref_is_large_binary():
            out["data_instances"] = self._native_data_refs(name)
            out["data_code_references"] = self._native_code_refs(name)
            for m in members:
                if len(out["code_references"]) >= _XREF_SCAN_MAX_MATCHES:
                    out["scan_truncated"] = True
                    break
                off = m.get("offset")
                if off is None:
                    continue
                for r in self._native_field_code_refs(name, off):
                    out["code_references"].append({
                        "function": r.get("function"),
                        "address": r.get("address"),
                        "text": r.get("text"),
                    })
            out["scan_skipped_large_binary"] = True
            return out

        # Gather globals with this union in their type string
        try:
            for var_addr in list(self._current_view.data_vars):
                try:
                    t = None
                    if hasattr(self._current_view, "get_type_at"):
                        t = self._current_view.get_type_at(var_addr)
                    t_str = str(t) if t is not None else ""
                    if t_str and name_l in t_str.lower():
                        sym = self._current_view.get_symbol_at(var_addr)
                        out["data_instances"].append(
                            {
                                "address": hex(var_addr),
                                "type": t_str,
                                "name": sym.name if sym else None,
                            }
                        )
                        # Code refs to that variable
                        try:
                            if hasattr(self._current_view, "get_code_refs"):
                                for ref in list(self._current_view.get_code_refs(var_addr)):
                                    fn_name = ref.function.name if getattr(ref, "function", None) else None
                                    out["data_code_references"].append(
                                        {
                                            "function": fn_name,
                                            "address": hex(ref.address),
                                            "target": hex(var_addr),
                                        }
                                    )
                        except Exception:
                            pass
                except Exception:
                    continue
        except Exception:
            pass

        # HLIL member access and casts; function variables/signatures
        try:
            import re
            patterns = []
            for m in members:
                nm = m.get("name")
                if not nm:
                    continue
                patterns.append(re.compile(rf"(\.|->)\s*{re.escape(str(nm))}(\b|\W)", re.IGNORECASE))

            for func in self._current_view.functions:
                if len(out["code_references"]) >= _XREF_SCAN_MAX_MATCHES:
                    break
                try:
                    # variables typed as this union
                    try:
                        for v in getattr(func, "vars", []):
                            try:
                                vtype = getattr(v, "type", None)
                                vname = getattr(v, "name", None)
                                vtype_str = str(vtype) if vtype is not None else ""
                                if vtype_str and name_l in vtype_str.lower():
                                    out["vars_with_type"].append(
                                        {
                                            "function": func.name,
                                            "var": vname,
                                            "type": vtype_str,
                                        }
                                    )
                            except Exception:
                                continue
                    except Exception:
                        pass

                    if hasattr(func, "hlil") and func.hlil:
                        for ins in func.hlil.instructions:
                            try:
                                text = str(ins)
                                tl = text.lower()
                                matched_member = any(p.search(text) for p in patterns) if patterns else False
                                if matched_member:
                                    out["code_references"].append(
                                        {
                                            "function": func.name,
                                            "address": hex(getattr(ins, "address", func.start)),
                                            "text": text,
                                        }
                                    )
                                # Capture casts mentioning the union
                                cast_matched = False
                                if name_l in tl:
                                    if re.search(rf"\(.*{re.escape(name)}.*\)", text, re.IGNORECASE):
                                        out["code_references_by_cast"].append(
                                            {
                                                "function": func.name,
                                                "address": hex(getattr(ins, "address", func.start)),
                                                "text": text,
                                            }
                                        )
                                        cast_matched = True
                                # Fallback: any HLIL mention of the union name counts as a code reference
                                if (not matched_member) and (not cast_matched) and (name_l in tl):
                                    out["code_references"].append(
                                        {
                                            "function": func.name,
                                            "address": hex(getattr(ins, "address", func.start)),
                                            "text": text,
                                        }
                                    )
                            except Exception:
                                continue
                    # function signature mentions
                    try:
                        sig_text = str(func.type)
                        if sig_text and name_l in sig_text.lower():
                            out["functions_with_type"].append(func.name)
                    except Exception:
                        pass
                except Exception:
                    continue
        except Exception:
            pass

        # Dedup functions list
        try:
            out["functions_with_type"] = sorted(list(set(out["functions_with_type"])) )
        except Exception:
            pass

        return out

    def patch_bytes(self, address: Union[str, int], data: Union[str, bytes, List[int]], save_to_file: bool = False) -> Dict[str, Any]:
        """Patch bytes at a given address in the binary.
        
        Args:
            address: Address to patch (hex string like "0x401000" or integer)
            data: Bytes to write. Can be:
                - Hex string: "90 90" or "9090" or "0x90 0x90"
                - List of integers: [0x90, 0x90]
                - Bytes object: b"\x90\x90"
            save_to_file: If True, save the patched binary to disk. REFUSED (saved_to_file
                False, save_refused True, save_error set; bv.save is never called) unless
                the server runs with BN_MCP_ALLOW_SAVE=1 (BinaryNinjaConfig.allow_save_to_file).
                The in-memory patch still applies and is recorded per view (raw_patches).

        Returns:
            Dictionary with status, address, original bytes, and patched bytes
            
        Raises:
            RuntimeError: If no binary is loaded
            ValueError: If address or data format is invalid
        """
        if not self._current_view:
            raise RuntimeError("No binary loaded")
        
        # Parse address
        # Only treat as hex if it has "0x" prefix or contains a-f/A-F characters
        # This avoids ambiguity where "123" would be treated as hex instead of decimal
        if isinstance(address, str):
            address = address.strip()
            if address.startswith("0x") or address.startswith("0X"):
                addr = int(address, 16)
            elif any(c in "abcdefABCDEF" for c in address):
                # Contains hex letters, treat as hex
                addr = int(address, 16)
            else:
                # Pure digits, treat as decimal
                addr = int(address, 10)
        else:
            addr = int(address)
        
        # Parse data into bytes
        patch_bytes = None
        if isinstance(data, bytes):
            patch_bytes = data
        elif isinstance(data, str):
            # Try to parse as hex string
            data_str = data.strip()
            # Remove "0x" prefix if present
            if data_str.startswith("0x"):
                data_str = data_str[2:]
            # Remove spaces
            data_str = data_str.replace(" ", "").replace("\n", "").replace("\t", "")
            # Convert hex string to bytes
            try:
                patch_bytes = bytes.fromhex(data_str)
            except ValueError as e:
                raise ValueError(f"Invalid hex string: {e}")
        elif isinstance(data, list):
            # List of integers
            try:
                patch_bytes = bytes(data)
            except (ValueError, TypeError) as e:
                raise ValueError(f"Invalid byte list: {e}")
        else:
            raise ValueError(f"Unsupported data type: {type(data)}")
        
        if not patch_bytes:
            raise ValueError("Empty patch data")
        
        # Read original bytes for comparison
        try:
            original_bytes = self._current_view.read(addr, len(patch_bytes))
            if original_bytes is None:
                original_bytes = b""
        except Exception as e:
            bn.log_warn(f"Could not read original bytes at {hex(addr)}: {e}")
            original_bytes = b""
        
        # Write the patch
        try:
            written = self._current_view.write(addr, patch_bytes)
            
            # Determine status based on whether all bytes were written
            if written != len(patch_bytes):
                bn.log_warn(f"Only wrote {written} of {len(patch_bytes)} bytes at {hex(addr)}")
                status = "partial"
            else:
                status = "ok"
            
            result = {
                "status": status,
                "address": hex(addr),
                "original_bytes": original_bytes.hex() if original_bytes else "",
                "patched_bytes": patch_bytes.hex(),
                "bytes_written": written,
                "bytes_requested": len(patch_bytes),
                "saved_to_file": False,
            }
            
            # Add warning message if partial write
            if status == "partial":
                result["warning"] = f"Only wrote {written} of {len(patch_bytes)} bytes"

            # Record the in-memory modification for this view (`_binary`.modified)
            try:
                n_written = int(written or 0)
            except Exception:
                n_written = 0
            if n_written > 0:
                try:
                    self._record_raw_patch(
                        self._current_view, addr,
                        (original_bytes or b"")[:n_written], patch_bytes[:n_written],
                    )
                except Exception as rec_e:
                    bn.log_warn(f"Could not record raw patch at {hex(addr)}: {rec_e}")

            # Save to file if requested (refused unless BN_MCP_ALLOW_SAVE=1)
            save_block = None
            if save_to_file:
                if not bool(getattr(self.config, "allow_save_to_file", False)):
                    save_block = (
                        "save_to_file refused by server policy: the patched image is never written "
                        "back to disk unless Binary Ninja runs with BN_MCP_ALLOW_SAVE=1; "
                        "the in-memory patch was applied"
                    )
                elif self._is_db(self._current_view) or self._backed_by_database(self._current_view):
                    # file.filename of a database session is the .bndb: BinaryView.save would write the raw
                    # patched image over the database.
                    save_block = (
                        "save_to_file refused: this view comes from a Binary Ninja database (.bndb), and saving "
                        "would write the raw patched image over the database file; save the database in "
                        "Binary Ninja instead. The in-memory patch was applied"
                    )
            if save_block:
                result["saved_to_file"] = False
                result["save_refused"] = True
                result["save_error"] = save_block
                bn.log_warn(f"patch_bytes: save_to_file refused at {hex(addr)}: {save_block}")
            elif save_to_file:
                try:
                    # Get the original file path
                    original_file = self._current_view.file.filename
                    if original_file:
                        # Save the patched binary back to the original file
                        if self._current_view.save(original_file):
                            result["saved_to_file"] = True
                            result["saved_path"] = original_file
                            bn.log_info(f"Patched binary saved to: {original_file}")
                            
                            # On macOS, re-sign the binary to avoid "killed" error
                            if platform.system() == "Darwin":
                                result["codesign"] = self._codesign_binary(original_file)
                        else:
                            bn.log_warn(f"Failed to save patched binary to: {original_file}")
                            result["save_error"] = "save() returned False"
                    else:
                        bn.log_warn("No original file path available for saving")
                        result["save_error"] = "No original file path"
                except Exception as save_e:
                    bn.log_warn(f"Failed to save patched binary: {save_e}")
                    result["save_error"] = str(save_e)
            
            return result
        except Exception as e:
            raise ValueError(f"Failed to patch bytes at {hex(addr)}: {str(e)}")

    def _codesign_binary(self, file_path: str) -> Dict[str, Any]:
        """Re-sign a binary on macOS after patching.
        
        On macOS, modifying a binary invalidates its code signature, causing the
        system to kill the process when executed. This method removes the old
        signature and applies an ad-hoc signature to make the binary executable.
        
        Args:
            file_path: Path to the binary file to sign
            
        Returns:
            Dictionary with codesign status and any error messages
        """
        result = {
            "attempted": True,
            "success": False,
            "platform": "macOS",
        }
        
        try:
            # Step 1: Remove existing signature (optional, codesign -f will overwrite anyway)
            remove_result = subprocess.run(
                ["codesign", "--remove-signature", file_path],
                capture_output=True,
                text=True,
                timeout=30,
                creationflags=_NO_WINDOW,
            )
            
            if remove_result.returncode != 0:
                # It's okay if removal fails (binary might not have been signed)
                bn.log_debug(f"codesign --remove-signature returned {remove_result.returncode}: {remove_result.stderr}")
            
            # Step 2: Apply ad-hoc signature with force flag
            sign_result = subprocess.run(
                ["codesign", "-f", "-s", "-", file_path],
                capture_output=True,
                text=True,
                timeout=30,
                creationflags=_NO_WINDOW,
            )
            
            if sign_result.returncode == 0:
                result["success"] = True
                result["message"] = "Binary re-signed with ad-hoc signature"
                bn.log_info(f"Successfully re-signed binary: {file_path}")
            else:
                result["error"] = sign_result.stderr or f"codesign failed with code {sign_result.returncode}"
                bn.log_warn(f"Failed to re-sign binary: {result['error']}")
                
        except FileNotFoundError:
            result["error"] = "codesign command not found"
            bn.log_warn("codesign command not found - is Xcode Command Line Tools installed?")
        except subprocess.TimeoutExpired:
            result["error"] = "codesign command timed out"
            bn.log_warn("codesign command timed out")
        except Exception as e:
            result["error"] = str(e)
            bn.log_warn(f"Error during codesign: {e}")
        
        return result
    
