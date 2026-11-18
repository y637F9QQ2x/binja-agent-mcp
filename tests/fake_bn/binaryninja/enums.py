# This file is part of binja-agent-mcp, a modified version of "Binary Ninja MCP" by fosdickio and
# CX330Blake (https://github.com/fosdickio/binary_ninja_mcp).
# Copyright (C) 2026 Kazuma Matsumoto
# SPDX-License-Identifier: GPL-3.0-or-later
# Not affiliated with or endorsed by Vector 35 Inc. This program comes with ABSOLUTELY NO WARRANTY.
"""Offline FAKE of binaryninja.enums (tests only; NOT Binary Ninja).

Only the enumerations the binja-agent-mcp plugin touches are modelled. Every enum is an
enum.IntEnum so the plugin's "report the analysis state by NAME" code path (AnalysisState(int(x)).name) is
exercised exactly as on the real API. Member VALUES follow the public Binary Ninja Python API where the plugin
depends on them (AnalysisState.IdleState == 2, ModificationStatus.Original == 0); the remaining values are only
required to be distinct.
"""

import enum


class AnalysisState(enum.IntEnum):
    InitialState = 0
    HoldState = 1
    IdleState = 2
    DiscoveryState = 3
    DisassembleState = 4
    AnalyzeState = 5
    ExtendedAnalyzeState = 6


class ModificationStatus(enum.IntEnum):
    Original = 0
    Changed = 1
    Inserted = 2


class SymbolType(enum.IntEnum):
    FunctionSymbol = 0
    ImportAddressSymbol = 1
    ImportedFunctionSymbol = 2
    DataSymbol = 3
    ImportedDataSymbol = 4
    ExternalSymbol = 5
    LibraryFunctionSymbol = 6
    SymbolicFunctionSymbol = 7
    LocalLabelSymbol = 8


class TypeClass(enum.IntEnum):
    VoidTypeClass = 0
    BoolTypeClass = 1
    IntegerTypeClass = 2
    FloatTypeClass = 3
    StructureTypeClass = 4
    EnumerationTypeClass = 5
    PointerTypeClass = 6
    ArrayTypeClass = 7
    FunctionTypeClass = 8
    VarArgsTypeClass = 9
    ValueTypeClass = 10
    NamedTypeReferenceClass = 11
    WideCharTypeClass = 12


class StructureVariant(enum.IntEnum):
    ClassStructureType = 0
    StructStructureType = 1
    UnionStructureType = 2


class RegisterValueType(enum.IntEnum):
    UndeterminedValue = 0
    EntryValue = 1
    ConstantValue = 2
    ConstantPointerValue = 3
    ExternalPointerValue = 4
    StackFrameOffset = 5
    ReturnAddressValue = 6
    ImportedAddressValue = 7
    SignedRangeValue = 8
    UnsignedRangeValue = 9
    LookupTableValue = 10
    InSetOfValues = 11
    NotInSetOfValues = 12


class DataFlowQueryOption(enum.IntEnum):
    FromAddressesInLookupTableQueryOption = 0
    AllowReadingWritableMemoryQueryOption = 1


class BranchType(enum.IntEnum):
    UnconditionalBranch = 0
    FalseBranch = 1
    TrueBranch = 2
    CallDestination = 3
    FunctionReturn = 4
    SystemCall = 5
    IndirectBranch = 6
    ExceptionBranch = 7
    UnresolvedBranch = 127
    UserDefinedBranch = 128


class ILBranchDependence(enum.IntEnum):
    NotBranchDependent = 0
    TrueBranchDependent = 1
    FalseBranchDependent = 2


class VariableSourceType(enum.IntEnum):
    StackVariableSourceType = 0
    RegisterVariableSourceType = 1
    FlagVariableSourceType = 2


class FunctionUpdateType(enum.IntEnum):
    UserFunctionUpdate = 0
    FullAutoFunctionUpdate = 1
    IncrementalAutoFunctionUpdate = 2


class SectionSemantics(enum.IntEnum):
    DefaultSectionSemantics = 0
    ReadOnlyCodeSectionSemantics = 1
    ReadOnlyDataSectionSemantics = 2
    ReadWriteDataSectionSemantics = 3
    ExternalSectionSemantics = 4


class SegmentFlag(enum.IntEnum):
    SegmentExecutable = 1
    SegmentWritable = 2
    SegmentReadable = 4
    SegmentContainsData = 8
    SegmentContainsCode = 16
    SegmentDenyWrite = 32
    SegmentDenyExecute = 64


class StringType(enum.IntEnum):
    AsciiString = 0
    Utf16String = 1
    Utf32String = 2
    Utf8String = 3


class AnalysisSkipReason(enum.IntEnum):
    NoSkipReason = 0
    AlwaysSkipReason = 1
    ExceedFunctionSizeSkipReason = 2
    ExceedFunctionAnalysisTimeSkipReason = 3
    ExceedFunctionUpdateCountSkipReason = 4
    NewAutoFunctionAnalysisSuppressedReason = 5
    BasicAnalysisSkipReason = 6
    IntermediateAnalysisSkipReason = 7


class FunctionAnalysisSkipOverride(enum.IntEnum):
    DefaultFunctionAnalysisSkip = 0
    NeverSkipFunctionAnalysis = 1
    AlwaysSkipFunctionAnalysis = 2


class InstructionTextTokenType(enum.IntEnum):
    TextToken = 0
    InstructionToken = 1
    OperandSeparatorToken = 2
    RegisterToken = 3
    IntegerToken = 4
    PossibleAddressToken = 5


def _il_ops(prefix, names):
    return enum.IntEnum(prefix + 'ILOperation', [(n, i) for i, n in enumerate(names)])


_COMMON = (
    'NOP', 'SET_VAR', 'VAR', 'ADDRESS_OF', 'ADDRESS_OF_FIELD', 'CONST', 'CONST_PTR', 'CONST_DATA', 'FLOAT_CONST',
    'IMPORT', 'EXTERN_PTR', 'ADD', 'SUB', 'MUL', 'AND', 'OR', 'XOR', 'LSL', 'LSR', 'ZX', 'SX', 'LOW_PART', 'LOAD',
    'STORE', 'JUMP', 'JUMP_TO', 'CALL', 'TAILCALL', 'SYSCALL', 'RET', 'NORET', 'IF', 'GOTO', 'CMP_E', 'CMP_NE',
    'CMP_SLT', 'CMP_ULT', 'CMP_SLE', 'CMP_ULE', 'CMP_SGE', 'CMP_UGE', 'CMP_SGT', 'CMP_UGT', 'TEST_BIT', 'BP',
    'TRAP', 'UNDEF', 'UNIMPL', 'INTRINSIC',
)

LowLevelILOperation = _il_ops('LowLevel', ['LLIL_' + n for n in _COMMON] + [
    'LLIL_SET_REG', 'LLIL_REG', 'LLIL_PUSH', 'LLIL_POP', 'LLIL_CALL_STACK_ADJUST', 'LLIL_SET_REG_SSA', 'LLIL_REG_SSA',
    'LLIL_CALL_SSA',
])

MediumLevelILOperation = _il_ops('MediumLevel', ['MLIL_' + n for n in _COMMON] + [
    'MLIL_SET_VAR_FIELD', 'MLIL_VAR_FIELD', 'MLIL_CALL_UNTYPED', 'MLIL_TAILCALL_UNTYPED',
    'MLIL_SET_VAR_SSA', 'MLIL_SET_VAR_SSA_FIELD', 'MLIL_SET_VAR_SPLIT_SSA', 'MLIL_SET_VAR_ALIASED',
    'MLIL_SET_VAR_ALIASED_FIELD', 'MLIL_VAR_SSA', 'MLIL_VAR_SSA_FIELD', 'MLIL_VAR_ALIASED', 'MLIL_VAR_ALIASED_FIELD',
    'MLIL_VAR_PHI', 'MLIL_MEM_PHI', 'MLIL_CALL_SSA', 'MLIL_CALL_UNTYPED_SSA', 'MLIL_TAILCALL_SSA', 'MLIL_SYSCALL_SSA',
    'MLIL_LOAD_SSA', 'MLIL_LOAD_STRUCT', 'MLIL_LOAD_STRUCT_SSA', 'MLIL_STORE_SSA', 'MLIL_STORE_STRUCT',
    'MLIL_STORE_STRUCT_SSA', 'MLIL_INTRINSIC_SSA', 'MLIL_MEMORY_INTRINSIC_SSA', 'MLIL_FREE_VAR_SLOT',
])

HighLevelILOperation = _il_ops('HighLevel', ['HLIL_' + n for n in _COMMON] + [
    'HLIL_BLOCK', 'HLIL_WHILE', 'HLIL_DO_WHILE', 'HLIL_FOR', 'HLIL_SWITCH', 'HLIL_CASE', 'HLIL_BREAK', 'HLIL_CONTINUE',
    'HLIL_ASSIGN', 'HLIL_VAR_INIT', 'HLIL_DEREF', 'HLIL_STRUCT_FIELD', 'HLIL_ARRAY_INDEX',
])


def il_operation(name):
    """The enum member for an IL operation name ('MLIL_CALL_SSA', 'HLIL_IF', ...). Raises KeyError when unknown."""
    if name.startswith('MLIL_'):
        return MediumLevelILOperation[name]
    if name.startswith('HLIL_'):
        return HighLevelILOperation[name]
    if name.startswith('LLIL_'):
        return LowLevelILOperation[name]
    raise KeyError(name)
