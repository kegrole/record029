"""Pickle opcode risk classification.

The detector is whitelist-based: only the opcodes listed in
DANGEROUS_OPCODES carry execution semantics. Everything else
(literal pushers, container builders, memo/stack plumbing, STOP)
is treated as inert data description.
"""

#: Opcodes with execution semantics. Any of these in a pickle stream
#: means the unpickler would resolve a global, call a callable, or
#: mutate object state -- i.e. the stream is code, not just data.
DANGEROUS_OPCODES = frozenset({
    "GLOBAL",        # pushes a module-level object by name (import happens)
    "STACK_GLOBAL",  # same as GLOBAL, operands from the stack
    "REDUCE",        # calls a callable: callable(*args)
    "INST",          # instantiates a class by name (protocol 0 style)
    "OBJ",           # instantiates a class from stack items
    "BUILD",         # applies __setstate__ / dict update to an object
    "NEWOBJ",        # cls.__new__(cls, *args)
    "NEWOBJ_EX",     # cls.__new__(cls, *args, **kwargs)
    "EXT1",          # resolves an extension-registry object by code
    "EXT2",          # same, 2-byte code
    "EXT4",          # same, 4-byte code
})

#: Short human-readable rationale per dangerous opcode, used in reports/docs.
DANGEROUS_REASONS = {
    "GLOBAL": "imports and pushes a module attribute by name",
    "STACK_GLOBAL": "imports and pushes a module attribute named on the stack",
    "REDUCE": "invokes a callable with arguments from the stack",
    "INST": "instantiates a class resolved by module/name strings",
    "OBJ": "instantiates a class object built on the stack",
    "BUILD": "applies state (__setstate__/dict update) to an object",
    "NEWOBJ": "calls cls.__new__ with attacker-controlled args",
    "NEWOBJ_EX": "calls cls.__new__ with attacker-controlled args/kwargs",
    "EXT1": "resolves an object from the pickle extension registry",
    "EXT2": "resolves an object from the pickle extension registry",
    "EXT4": "resolves an object from the pickle extension registry",
}


def is_dangerous(opcode_name):
    """Return True if the opcode name carries execution semantics."""
    return opcode_name in DANGEROUS_OPCODES
