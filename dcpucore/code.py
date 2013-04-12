# -*- coding: utf-8 -*-
"""
dcpucore.code
=============
Metadata and tools for manipulating instructions.

:copyright: (C) 2013 Matthew Frazier
:license:   MIT/X11 -- see the LICENSE file for details
"""
import itertools

#: A constant that indicates a binary (two-argument) opcode.
BINARY = "binary"

#: A constant that indicates a special (one-argument, lower 5 bits 0) opcode.
SPECIAL = "special"


class Opcode(object):
    """
    A set of information about a specific operation supported by the DCPU-16.

    :param type: The opcode type (`BINARY` for a normal binary opcode,
                 `SPECIAL` for a special opcode).
    :param number: The numeric value for this opcode.
    :param mnemonic: The assembler mnemonic (such as SET or ADX).
    :param cost: The base cost for this opcode (not including decode cost).
    :param comment: A human-readable explanation of what the opcode does.
    """
    __slots__ = ('type', 'number', 'mnemonic', 'cost', 'comment')

    def __init__(self, type, number, mnemonic, cost, comment=None):
        self.type = type
        self.number = number
        self.mnemonic = mnemonic
        self.cost = cost
        self.comment = comment

    def __repr__(self):
        return "Opcode(%r, %r, %r, %r, %r)" % (
            self.type, self.number, self.mnemonic, self.cost, self.comment
        )

    def __str__(self):
        return "%s (%s %02x)" % (self.mnemonic, self.type, self.number)


class InstructionSet(object):
    """
    A container for DCPU instruction set metadata. This assumes the
    instruction formats and addressing modes are treated as in the
    DCPU 1.7 spec.

    These aren't intended to be modified while in use. There's nothing
    *preventing* you from doing so, but be aware that there may be strange
    consequences.

    Iterating over this will iterate over all registered `Opcode`\s (not
    necessarily in order).

    :param opcodes: The opcodes to load.
    """
    def __init__(self, opcodes=None):
        #: A `dict` whose keys are opcode types and whose values are `dict`\s
        #: mapping numbers to `Opcode`\s.
        self.opcodes = {}
        self.fill_blanks()

        #: A `dict` whose keys are mnemonics and whose values are `Opcode`\s.
        self.by_mnemonic = {}

        for opcode in opcodes:
            self.register(opcode, False)

    def __iter__(self):
        return itertools.chain(*self.opcodes.values())

    def fill_blanks(self):
        """
        Reserves space in the `opcodes` dictionary for each opcode.
        """
        self.opcodes[BINARY] = dict((n, None) for n in range(0x01, 0x20))
        self.opcodes[SPECIAL] = dict((n, None) for n in range(0x01, 0x20))

    def register(self, opcode, replace=True):
        """
        Registers an opcode in the instruction set.

        :param opcode: The `Opcode` object with the opcode's metadata.
        :param replace: If `True`, if this opcode has the same type and
                        number as another, it will replace it
                        (unless the mnemonic conflicts with a *different*
                        opcode). If `False`, an exception will be raised.
        """
        # Check that it's a valid opcode.
        if not isinstance(opcode, Opcode):
            raise TypeError("You can only register Opcodes")

        # Check that it's compatible with our instruction set.
        if opcode.type not in self.opcodes:
            raise ValueError("The type %r is not valid" % opcode.type)
        if opcode.number not in self.opcodes[opcode.type]:
            raise ValueError("0x%02x is not in range for %s opcodes" %
                             (opcode.number, opcode.type))

        # Check that it doesn't overwrite another opcode.
        existing_opcode = self.opcodes[opcode.type][opcode.number]
        if existing_opcode is not None and not overwrite:
            raise KeyError("Will not overwrite %s" % existing_opcode)

        # Check that the mnemonic doesn't clash with another.
        # (Though it's okay if we're overwriting an opcode and using the
        # same mnemonic as the old one.)
        if (opcode.mnemonic in self.by_mnemonic and
                    self.by_mnemonic[opcode_mnemonic] is not existing_opcode):
            raise KeyError("Mnemonic conflicts with %s" %
                           self.by_mnemonic[opcode.mnemonic])

        self.opcodes[opcode.type][opcode.number] = opcode
        self.by_mnemonic[opcode.mnemonic] = opcode


#: A list of `Opcode` instances for the DCPU-16 1.7 standard.
DCPU_17_OPCODES = (
    Opcode(BINARY,  0x01,   "SET",  1,  "set"),

    Opcode(BINARY,  0x02,   "ADD",  2,  "add"),
    Opcode(BINARY,  0x03,   "SUB",  2,  "subtract"),

    Opcode(BINARY,  0x04,   "MUL",  2,  "unsigned multiply"),
    Opcode(BINARY,  0x05,   "MLI",  2,  "signed multiply"),
    Opcode(BINARY,  0x06,   "DIV",  3,  "unsigned divide"),
    Opcode(BINARY,  0x07,   "DVI",  3,  "signed divide"),
    Opcode(BINARY,  0x08,   "MOD",  3,  "unsigned modulus"),
    Opcode(BINARY,  0x09,   "MDI",  3,  "signed modulus"),

    Opcode(BINARY,  0x0a,   "AND",  1,  "bitwise and"),
    Opcode(BINARY,  0x0b,   "BOR",  1,  "bitwise or"),
    Opcode(BINARY,  0x0c,   "XOR",  1,  "bitwise exclusive or"),

    Opcode(BINARY,  0x0d,   "SHR",  1,  "logical shift right"),
    Opcode(BINARY,  0x0e,   "ASR",  1,  "arithmetic shift right"),
    Opcode(BINARY,  0x0f,   "SHL",  1,  "logical shift left"),

    Opcode(BINARY,  0x10,   "IFB",  2,  "if masked bits set"),
    Opcode(BINARY,  0x11,   "IFC",  2,  "if masked bits clear"),
    Opcode(BINARY,  0x12,   "IFE",  2,  "if equal"),
    Opcode(BINARY,  0x13,   "IFN",  2,  "if not equal"),
    Opcode(BINARY,  0x14,   "IFG",  2,  "if greater than (unsigned)"),
    Opcode(BINARY,  0x15,   "IFA",  2,  "if greater than (signed)"),
    Opcode(BINARY,  0x16,   "IFL",  2,  "if less than (unsigned)"),
    Opcode(BINARY,  0x17,   "IFU",  2,  "if less than (signed)"),

    Opcode(BINARY,  0x1a,   "ADX",  3,  "add with EX (carry)"),
    Opcode(BINARY,  0x1b,   "SBX",  3,  "subtract with EX (borrow)"),

    Opcode(BINARY,  0x1e,   "STI",  2,  "set then increment I, J"),
    Opcode(BINARY,  0x1f,   "STD",  2,  "set then decrement I, J"),


    Opcode(SPECIAL, 0x01,   "JSR",  3,  "jump and set return"),

    Opcode(SPECIAL, 0x08,   "INT",  4,  "trigger software interrupt"),
    Opcode(SPECIAL, 0x09,   "IAG",  1,  "get interrupt handler address"),
    Opcode(SPECIAL, 0x0a,   "IAS",  1,  "set interrupt handler address"),
    Opcode(SPECIAL, 0x0b,   "RFI",  3,  "return from interrupt handler"),
    Opcode(SPECIAL, 0x0c,   "IAQ",  2,  "enable/disable interrupt queue"),

    Opcode(SPECIAL, 0x10,   "HWN",  2,  "count hardware devices"),
    Opcode(SPECIAL, 0x11,   "HWQ",  4,  "get hardware information"),
    Opcode(SPECIAL, 0x12,   "HWI",  4,  "send hardware interrupt")
)


#: An instruction set for the DCPU-16 1.7 standard.
DCPU_17 = InstructionSet(DCPU_17_OPCODES)
