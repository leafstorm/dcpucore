# -*- coding: utf-8 -*-
"""
dcpucore.code
=============
Metadata and tools for manipulating instructions.

:copyright: (C) 2013 Matthew Frazier
:license:   MIT/X11 -- see the LICENSE file for details
"""
from .words import WORD_ARRAY, unsign_word
import abc
import array
import itertools

#: A constant that indicates a binary (two-argument) opcode.
BINARY = "binary"

#: A constant that indicates a special (one-argument, lower 5 bits 0) opcode.
SPECIAL = "special"


#: A string with the names of the DCPU's 8 registers, in order.
REGISTERS = "ABCXYZIJ"


def show_displacement(n):
    if isinstance(n, str):
        return n
    elif n < 10:
        return str(n)
    elif n > 0xfff6:
        return str(0x10000 - n)
    else:
        return hex(n)


def show_maybe_address(n):
    if isinstance(n, str):
        return n
    elif n < 10:
        return str(n)
    elif n > 0xfff6:
        return str(0x10000 - n)
    else:
        return "0x%04x" % n


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
    #: A `tuple` of the instruction set's general registers.
    #: Their appearance in this order should indicate their register number.
    GENERAL_REGISTERS = tuple("ABCXYZIJ")

    #: A `frozenset` of the processor's special registers, so long as
    #: they have write context.
    #: (It's a `frozenset` because order insignificant.)
    SPECIAL_REGISTERS = frozenset(("EX", "PC", "SP"))

    #: A `frozenset` of special address operations.
    SPECIAL_OPERATIONS = frozenset(("PUSH", "POP", "PICK"))

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
        # Special opcode 0x00 is "reserved for future expansion,"
        # but it's useful to allow it to be overridden until Notch
        # defines a new kind of opcode for it.
        self.opcodes[SPECIAL] = dict((n, None) for n in range(0x00, 0x20))

    def get_reserved_words(self):
        reserved = set()
        reserved.update(GENERAL_REGISTERS, SPECIAL_REGISTERS,
                        SPECIAL_OPERATIONS, self.by_mnemonic.keys())
        return reserved

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

    def decode_instruction(self, buffer, offset=None, wrap=True):
        """
        Decodes a complete instruction from the buffer. It will return
        an `Instruction` object. (You can use the length of its
        `~Instruction.source` attribute to advance the offset.)

        :param buffer: A buffer of words to read the instruction from.
        :param offset: The index to the start of the instruction within
                       `buffer`.
        :param wrap: If `True` (the default), reading past the buffer
                     will result in it wrapping around. If `False`, no
                     wrapping will be done, so you'll probably get an
                     `IndexError`.
        """
        buflen = len(buffer)
        source = array.array(WORD_ARRAY)

        if offset is None:
            offset = 0
            start_offset = None
        else:
            start_offset = offset

        code_word = buffer[offset]
        source.append(code_word)
        offset = (offset + 1) % buflen if wrap else offset + 1

        opcode_number = code_word & 0x1f
        if opcode_number == 0:
            # Special instruction
            spec_opcode_number = (code_word >> 5) & 0x1f
            opcode = self.opcodes[SPECIAL][spec_opcode_number]

            a_code = code_word >> 10
            if offset < buflen:
                a, word_used = self._decode_address(a_code, buffer[offset])
                if word_used:
                    source.append(buffer[offset])
                    offset = (offset + 1) % buflen if wrap else offset + 1
            else:
                a, word_used = self._decode_address(a_code, 0x0000)
                if word_used:
                    raise IndexError("address %02x required a read past "
                                     "the end of the buffer" % a_code)

            return SpecialInstruction(opcode, a, start_offset, source)

        else:
            # Binary instruction
            opcode = self.opcodes[BINARY][opcode_number]

            a_code = (code_word >> 5) & 0x1f
            if offset < buflen:
                a, word_used = self._decode_address(a_code, buffer[offset])
                if word_used:
                    source.append(buffer[offset])
                    offset = (offset + 1) % buflen if wrap else offset + 1
            else:
                a, word_used = self._decode_address(a_code, 0x0000)
                if word_used:
                    raise IndexError("address %02x required a read past "
                                     "the end of the buffer" % a_code)

            b_code = code_word >> 10
            if offset < buflen:
                b, word_used = self._decode_address(b_code, buffer[offset])
                if word_used:
                    source.append(buffer[offset])
                    offset = (offset + 1) % buflen if wrap else offset + 1
            else:
                b, word_used = self._decode_address(b_code, 0x0000)
                if word_used:
                    raise IndexError("address %02x required a read past "
                                     "the end of the buffer" % b_code)

            return BinaryInstruction(opcode, a, b, start_offset, source)

    def _decode_address(self, lead, next_word):
        if lead >= 0x20:
            # Quick immediate value (-1 to 30)
            return QuickImmediate(unsign_word((lead & 0x1f) - 1)), False
        elif lead >= 0x18:
            # Special value
            if lead == 0x18:
                return PUSHPOP, False
            elif lead == 0x19:
                return PEEK, False
            elif lead == 0x1a:
                return Pick(next_word), True
            elif lead == 0x1b:
                return SP, False
            elif lead == 0x1c:
                return PC, False
            elif lead == 0x1d:
                return EX, False
            elif lead == 0x1e:
                return Displacement(next_word), True
            elif lead == 0x1f:
                return Immediate(next_word), True
        else:
            # Register-linked value
            control = lead & 0x18
            if lead == 0x10:
                # [Register + displacement]
                return RegisterIndirectDisplaced(lead & 0x07, next_word), True
            elif lead == 0x08:
                # [Register]
                return RegisterIndirect(lead & 0x07), False
            else:
                # Register
                return Register(lead & 0x07), False


class Instruction(object):
    """
    This is the base class for instructions.
    """
    __metaclass__ = abc.ABCMeta
    __slots__ = ('offset', 'source',)

    @abc.abstractmethod
    def assemble(self, symbols=None):
        """
        This will assemble this instruction into machine code.

        :param symbols: A dictionary of symbols to look for label values in.
                        (This won't be a problem unless there are labels.)
        """

    @abc.abstractproperty
    def size(self):
        """
        Returns the encoded size of this instruction.
        (This should be the same independent of any symbols provided.)
        """
        pass


class BinaryInstruction(Instruction):
    """
    This class holds a binary instruction -- an opcode, and two arguments
    `a` and `b`.
    """
    __slots__ = ('opcode', 'b', 'a')

    def __init__(self, opcode, b, a, offset=None, source=None):
        #: The `Opcode` this instruction is for.
        self.opcode = opcode
        #: The `Address` pointing to this instruction's b argument.
        self.b = b
        #: The `Address` pointing to this instruction's a argument.
        self.a = a
        #: The offset this instruction was decoded from.
        self.offset = offset
        #: An `array.array` of words this instruction was decoded from.
        self.source = source

    def __str__(self):
        return "%s %s, %s" % (self.opcode.mnemonic, self.b, self.a)

    def assemble(self, symbols=None):
        data = array.array(WORD_ARRAY)
        b_code, b_next = self.b.assemble(symbols)
        a_code, a_next = self.a.assemble(symbols)
        data.append(self.opcode.number | (a_code << 10) | (b_code << 5))
        if a_next is not None:
            data.append(a_next)
        if b_next is not None:
            data.append(b_next)
        return data

    @property
    def size(self):
        return (1 + (1 if self.b.uses_next else 0) +
                    (1 if self.a.uses_next else 0))


class SpecialInstruction(Instruction):
    """
    This class holds a special instruction -- an opcode, and a single `a`
    instruction.
    """
    __slots__ = ('opcode', 'a')

    def __init__(self, opcode, a, offset=None, source=None):
        #: The `Opcode` this instruction is for.
        self.opcode = opcode
        #: The `Address` pointing to this instruction's a argument.
        self.a = a
        #: The offset this instruction was decoded from.
        self.offset = offset
        #: An `array.array` of words this instruction was decoded from.
        self.source = source

    def __str__(self):
        return "%s %s" % (self.opcode.mnemonic, self.a)

    def assemble(self, symbols=None):
        data = array.array(WORD_ARRAY)
        a_code, a_next = self.a.assemble(symbols)
        data.append((self.opcode.number << 5) | (a_code << 10))
        if a_next is not None:
            data.append(a_next)
        return data

    @property
    def size(self):
        return 1 + (1 if self.a.uses_next else 0)


def resolve_symbol(sym, symbols):
    if isinstance(sym, basestring):
        if symbols is None or sym not in symbols:
            raise NameError("Undefined symbol '%s'" % sym)
        return symbols[sym]
    return sym


class Address(object):
    """
    This class represents addresses. Each subclass corresponds to an
    addressing mode.
    """
    __metaclass__ = abc.ABCMeta
    __slots__ = ()

    def __str__(self):
        return self.display_load()

    @abc.abstractmethod
    def display_load(self):
        """
        The string representation of this address in a load context.
        """

    def display_store(self):
        """
        The string representation of this address in a store context.
        (Usually this will be the same as `display_load`.)
        """
        return self.display_load()

    @abc.abstractmethod
    def assemble(self, symbols=None):
        """
        Returns the encoded version of this address, as a
        ``(value_code, next_word)`` tuple (with the next word being `None`
        if there isn't one).
        """

    #: Whether the instruction uses the next words.
    uses_next = False

    #: The extra cost in clock cycles incurred by decoding this address.
    decode_cost = 0


class Register(Address):
    """
    An `Address` to the contents of a register (ABCXYZIJ).

    :param register: The index number of the register to access.
    """
    __slots__ = ('register',)

    def __init__(self, register):
        self.register = register

    def display_load(self):
        return REGISTERS[self.register]

    def assemble(self, symbols=None):
        return 0x00 + self.register, None


class RegisterIndirect(Address):
    """
    An `Address` for the memory address stored in a register (ABCXYZIJ).

    :param register: The index number of the register to access.
    """
    __slots__ = ('register',)

    def __init__(self, register):
        self.register = register

    def display_load(self):
        return "[" + REGISTERS[self.register] + "]"

    def assemble(self, symbols=None):
        return 0x08 + self.register, None


class RegisterIndirectDisplaced(Address):
    """
    An `Address` for the memory address at a constant offset from an
    address stored in a register (ABCXYZIJ).

    :param register: The index number of the register to access.
    :param displacement: The offset to access from the original value
    """
    __slots__ = ('register', 'displacement',)

    def __init__(self, register, displacement):
        self.register = register
        self.displacement = displacement

    def display_load(self):
        return "[%s + %s]" % (REGISTERS[self.register],
                              show_displacement(self.displacement))

    def assemble(self, symbols=None):
        return 0x10 + self.register, resolve_symbol(self.displacement, symbols)

    uses_next = True
    decode_cost = 1


class PushPopAddress(Address):
    __slots__ = ()

    def display_load(self):
        return "POP"

    def display_store(self):
        return "PUSH"

    def assemble(self, symbols=None):
        return 0x18, None


#: An `Address` that pushes values on the stack in store context,
#: and pops them in load context.
PUSHPOP = PushPopAddress()


class PeekAddress(Address):
    __slots__ = ()

    def display_load(self):
        return "[SP]"

    def assemble(self, symbols=None):
        return 0x19, None


#: An `Address` that refers to the stack top.
PEEK = PeekAddress()


class Pick(Address):
    """
    An `Address` mode that accesses a word at a position relative to the
    stack pointer (SP).

    :param displacement: The distance from SP.
    """
    __slots__ = ('displacement',)

    def __init__(self, displacement):
        self.displacement = displacement

    def display_load(self):
        return "[SP + %s]" % show_displacement(self.displacement)

    def assemble(self, symbols=None):
        return 0x1a, resolve_symbol(self.displacement, symbols)

    uses_next = True
    decode_cost = 1


class SpecialRegister(Address):
    __slots__ = ('name', 'code')

    def __init__(self, name, code):
        self.name = name
        self.code = code

    def display_load(self):
        return self.name

    def assemble(self, symbols=None):
        return self.code, None


#: The `Address` representing the SP (stack pointer) register.
SP = SpecialRegister("SP", 0x1b)

#: The `Address` representing the PC (program counter) register.
PC = SpecialRegister("PC", 0x1c)

#: The `Address` representing the EX (excess/overflow) register.
EX = SpecialRegister("EX", 0x1d)


class Displacement(Address):
    """
    An `Address` that refers to a specific location in memory.

    :param address: The address to access.
    """
    __slots__ = ('address',)

    def __init__(self, address):
        self.address = address

    def display_load(self):
        if isinstance(self.address, str):
            return "[%s]" % self.address
        return "[0x%04x]" % self.address

    def assemble(self, symbols=None):
        return 0x1e, resolve_symbol(self.address, symbols)

    uses_next = True
    decode_cost = 1


class Immediate(Address):
    """
    An `Address` that simply holds a constant value.

    :param value: The value of the constant to access.
    """
    __slots__ = ('value',)

    def __init__(self, value):
        self.value = value

    def display_load(self):
        return show_maybe_address(self.value)

    def assemble(self, symbols=None):
        return 0x1f, resolve_symbol(self.value, symbols)

    uses_next = True
    decode_cost = 1


class QuickImmediate(Immediate):
    """
    Like `Immediate`, but faster.
    """
    __slots__ = ()

    def assemble(self, symbols=None):
        return 0x21 + self.value, None

    uses_next = False
    decode_cost = 0


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
