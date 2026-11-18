# This file is part of binja-agent-mcp, a modified version of "Binary Ninja MCP" by fosdickio and
# CX330Blake (https://github.com/fosdickio/binary_ninja_mcp).
# Copyright (C) 2026 Kazuma Matsumoto
# SPDX-License-Identifier: GPL-3.0-or-later
# Not affiliated with or endorsed by Vector 35 Inc. This program comes with ABSOLUTELY NO WARRANTY.
"""Offline FAKE of the `binaryninja` Python package (tests only; this is NOT Binary Ninja).

run_tests.py puts the directory that holds this package FIRST on sys.path, so the Binary Ninja MCP plugin's
`import binaryninja as bn` binds to this fake. The fake models only the API the plugin touches (see
binaryview.py for the object model and enums.py for the enumerations); everything else is absent on purpose,
so a plugin path that depends on an unmodelled member fails loudly in the tests instead of passing by accident.

Module-level test hooks (never part of the real API):
  LOGS         a bounded deque of (level, message) from log_info/log_warn/log_error/log_debug/log_alert
  LOAD_HOOK    None, or callable(path, options) -> BinaryView | None, consulted first by load()
  LOAD_CALLS   every (path, options) load() received
  CORE_VERSION the string core_version() returns
  PluginCommand.REGISTERED  every menu command the plugin registered
"""

import collections
import sys
import threading
import types as _types

from . import enums
from . import binaryview
from .enums import (                                                    # noqa: F401  (re-exported like the real API)
    AnalysisState, BranchType, DataFlowQueryOption, FunctionUpdateType, ILBranchDependence, ModificationStatus,
    RegisterValueType, SectionSemantics, SegmentFlag, StringType, StructureVariant, SymbolType, TypeClass,
    VariableSourceType, LowLevelILOperation, MediumLevelILOperation, HighLevelILOperation,
)
from .binaryview import (                                               # noqa: F401
    BinaryView, Function, FileMetadata, PossibleValueSet, ValueRange, Symbol, SSAVariable, Variable,
    BasicBlock, ILFunction, ILNode, Architecture, Platform, StringReference, ReferenceSource,
)

# The names the real package exports and the plugin imports from it (re-exported here).
__all__ = [
    'enums', 'binaryview',
    'AnalysisState', 'BranchType', 'DataFlowQueryOption', 'FunctionUpdateType', 'ILBranchDependence',
    'ModificationStatus', 'RegisterValueType', 'SectionSemantics', 'SegmentFlag', 'StringType', 'StructureVariant',
    'SymbolType', 'TypeClass', 'VariableSourceType', 'LowLevelILOperation', 'MediumLevelILOperation',
    'HighLevelILOperation',
    'BinaryView', 'Function', 'FileMetadata', 'PossibleValueSet', 'ValueRange', 'Symbol', 'SSAVariable', 'Variable',
    'BasicBlock', 'ILFunction', 'ILNode', 'Architecture', 'Platform', 'StringReference', 'ReferenceSource',
    'PluginCommand', 'QualifiedName', 'load', 'open_view', 'core_version', 'log_info', 'log_warn', 'log_error',
    'log_debug', 'log_alert', 'execute_on_main_thread', 'execute_on_main_thread_and_wait', 'mainthread',
    'mediumlevelil', 'variable',
]

CORE_VERSION = '6.0.10601-offline-fake'
LOGS = collections.deque(maxlen=20000)
LOAD_HOOK = None
LOAD_CALLS = []
_LOAD_LOCK = threading.Lock()


def _log(level, msg):
    LOGS.append((level, str(msg)))


def log_info(msg, *args, **kwargs):
    _log('info', msg)


def log_warn(msg, *args, **kwargs):
    _log('warn', msg)


def log_error(msg, *args, **kwargs):
    _log('error', msg)


def log_debug(msg, *args, **kwargs):
    _log('debug', msg)


def log_alert(msg, *args, **kwargs):
    _log('alert', msg)


def core_version():
    return CORE_VERSION


def load(source, update_analysis=True, progress_func=None, options=None, **kwargs):
    """binaryninja.load(path, update_analysis=True, options={...}) -> BinaryView (the fake loader)."""
    with _LOAD_LOCK:
        LOAD_CALLS.append((str(source), dict(options) if isinstance(options, dict) else options))
        hook = LOAD_HOOK
    if hook is not None:
        v = hook(str(source), options)
        if v is not None:
            return v
    return binaryview.open_view(str(source), options)


def open_view(source, update_analysis=True, progress_func=None, options=None, **kwargs):
    """The pre-6.0 entry point the upstream (baseline) plugin calls first."""
    return load(source, update_analysis, progress_func, options)


class QualifiedName(object):
    def __init__(self, name=''):
        self.name = [name] if isinstance(name, str) else list(name)

    def __str__(self):
        return '::'.join(self.name)


class PluginCommand(object):
    """binaryninja.PluginCommand registration (shapes of the real class methods). Every call is recorded in
    REGISTERED as (method, name, description, action); test_plugin_glue removes register_global to model a build
    without it."""
    REGISTERED = []

    @classmethod
    def register(cls, name, description, action, is_valid=None):
        cls.REGISTERED.append(('register', name, description, action))

    @classmethod
    def register_global(cls, name, description, action, is_valid=None):
        cls.REGISTERED.append(('register_global', name, description, action))


# binaryninja.mediumlevelil / binaryninja.variable: the plugin imports SSAVariable, PossibleValueSet and ValueRange
# from these submodules; they are registered here (this fake has no separate files for them).
mediumlevelil = _types.ModuleType(__name__ + '.mediumlevelil')
mediumlevelil.SSAVariable = SSAVariable
mediumlevelil.MediumLevelILOperation = MediumLevelILOperation
sys.modules[mediumlevelil.__name__] = mediumlevelil

variable = _types.ModuleType(__name__ + '.variable')
variable.PossibleValueSet = PossibleValueSet
variable.ValueRange = ValueRange
variable.Variable = Variable
sys.modules[variable.__name__] = variable


# ---------------------------------------------------------------------------------------------------------------------
# Main-thread dispatch doubles (never part of the real API's behaviour; shapes only): execute_on_main_thread /
# execute_on_main_thread_and_wait record every call in MAIN_THREAD_CALLS (the HTTP request path must never make one)
# and run the function inline.
# ---------------------------------------------------------------------------------------------------------------------
MAIN_THREAD_CALLS = []


def execute_on_main_thread(func):
    MAIN_THREAD_CALLS.append(('execute_on_main_thread', getattr(func, '__name__', '?')))
    func()


def execute_on_main_thread_and_wait(func):
    MAIN_THREAD_CALLS.append(('execute_on_main_thread_and_wait', getattr(func, '__name__', '?')))
    func()


mainthread = _types.ModuleType(__name__ + '.mainthread')
mainthread.execute_on_main_thread = execute_on_main_thread
mainthread.execute_on_main_thread_and_wait = execute_on_main_thread_and_wait
sys.modules[mainthread.__name__] = mainthread
