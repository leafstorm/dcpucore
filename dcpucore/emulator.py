# -*- coding: utf-8 -*-
"""
dcpucore.emulator
=================
The actual DCPU emulator.

:copyright: (C) 2013 Matthew Frazier
:license:   MIT/X11 -- see the LICENSE file for details
"""
from __future__ import division
import array
from collections import deque
from functools import wraps
from .code import (DCPU_17, resolve_symbol,
                   BinaryInstruction, SpecialInstruction,
                   Register, RegisterIndirect, RegisterIndirectDisplaced,
                   Displacement, Immediate, QuickImmediate,
                   PUSHPOP, PEEK, Pick, SP, PC, EX)
from .words import (WORD_ARRAY, WORD_MASK, WORD_MAX, sign_word,
                    DWORD_MASK, sign_dword)

A, B, C, X, Y, Z, I, J = range(8)

INT_QUEUE_ENABLED = 0
INT_QUEUE_EMPTY = 1
INT_NO_HANDLER = 2
INT_DELIVERED = 3


class Emulator(object):
    """
    This represents a running DCPU-16.

    :param instruction_set: The instruction set to use. It defualts to
                            `dcpucore.code.DCPU_17`.
    """
    def __init__(self, instruction_set=None):
        #: The instruction set used by this DCPU-16.
        self.isa = instruction_set or DCPU_17

        #: Methods to be invoked when running an instruction.
        self.opcode_handlers = {}
        for mnemonic, opcode in self.isa.by_mnemonic.items():
            if hasattr(self, mnemonic):
                self.opcode_handlers[opcode] = getattr(self, mnemonic)

        #: The general-purpose register array.
        self.registers = array.array(WORD_ARRAY, (0 for r in range(8)))
        #: The SP (stack pointer) register.
        self.sp = 0
        #: The PC (program counter) register.
        self.pc = 0
        #: The EX (overflow) register.
        self.ex = 0
        #: The IA (interrupt handler address) register.
        self.ia = 0

        #: The number of cycles this machine has executed as part of a `step`.
        self.cycles = 0
        #: If this is `True`, the machine will not execute any `step`\s.
        self.halted = False
        #: If this is `True`, the machine has ignited.
        self.on_fire = False

        #: The memory array.
        self.memory = array.array(WORD_ARRAY, (0 for n in range(0x10000)))

        #: The interrupt queue. This is a `collections.deque`.
        self.int_queue = deque((), 256)
        #: Whether interrupt queueing is enabled.
        self.int_queue_enabled = False

        #: The list of connected hardware devices.
        self.hardware = []


    ### MEMORY MANAGEMENT ###

    def read(self, buffer, offset=0):
        """
        Reads data from a buffer of words into the DCPU's memory.

        :param buffer: A buffer of words to store into memory.
        :param offset: The offset to start writing at. This defaults to
                       0 (the start of memory).
        """
        for word in buffer:
            self.memory[offset] = word
            offset = (offset + 1) & WORD_MASK

    def clear_memory(self):
        """
        Resets memory to be filled entirely with 0's.
        """
        self.memory = array.array(WORD_ARRAY, (0 for n in range(0x10000)))


    ### MACHINE STATE MANAGEMENT ###

    def ignite(self):
        """
        Sets the `on_fire` flag to `True`. (By default, this has no effect.
        However, you can consult the `on_fire` flag in subclasses and/or
        hardware, or override this method to do something upon ignition.)
        """
        self.on_fire = True

    def execute(self, instruction):
        """
        Runs an instruction, and returns the number of cycles it took.
        This will not affect PC, unless the instruction directly sets or
        otherwise modifies PC.

        :param instruction: The instruction to run.
        """
        opcode = instruction.opcode
        if opcode not in self.opcode_handlers:
            return 0
        elif opcode.type == 'special':
            return self.opcode_handlers[opcode](instruction, instruction.a)
        elif opcode.type == 'binary':
            return self.opcode_handlers[opcode](instruction,
                                                instruction.b, instruction.a)
        else:
            raise ValueError("Invalid operation type")

    def step(self):
        """
        Executes a normal step for the processor. This will read and decode
        an instruction from RAM, advance PC, execute it, add it to the
        cycle counter, and trigger an interrupt if one is queued.

        The return value is the cost of the instruction. However, if the
        DCPU is halted (the `halted` flag is `True`), this will return `None`.
        """
        # Check if the machine is halted first.
        if self.halted:
            return False

        # Read and decode an instruction.
        inst = self.isa.decode_instruction(self.memory, self.pc)
        self.pc = (self.pc + inst.size) & WORD_MASK

        # Run the instruction and log the cost.
        cost = self.execute(inst)
        self.cycles += cost

        # Trigger an interrupt before returning.
        self.trigger_interrupt()

        return cost

    def decode_instruction(self, offset=None):
        """
        Reads and returns an instruction from memory.

        :param offset: The offset to read the instruction at.
                       The default is to read the current program counter.
        """
        offset = self.pc if offset is None else offset
        return self.isa.decode_instruction(self.memory, offset)

    def skip_instructions(self):
        """
        Advances PC past the current instruction. If the current instruction
        is a conditional (IFX) instruction, it will skip the next one as well.
        It returns the number of instructions skipped.
        """
        skip_count = 1
        while True:
            lead = self.memory[self.pc]
            size = self.isa.get_instruction_size(lead)
            self.pc = (self.pc + size) & WORD_MASK
            if not self.isa.is_conditional_instruction(lead):
                break
            skip_count += 1
        return skip_count


    ### INTERRUPTS ###

    def interrupt(self, message):
        """
        Sends an interrupt to the DCPU. This will store the interrupt in its
        interrupt queue, to be delivered by a later `trigger_interrupt`
        (which happens as part of `step`).

        This will return `True` if the interrupt was queued successfully,
        and `False` if it was dropped (and is guaranteed to never trigger).

        :param message: The interrupt message to deliver.
        """
        if self.int_queue < self.int_queue.maxlen:
            self.int_queue.append(message & WORD_MASK)
            return True
        else:
            return self.on_queue_full(message & WORD_MASK)

    def on_queue_full(self, message):
        """
        Invoked when `interrupt` is called and the interrupt queue is full.
        The default behavior is to discard the interrupt and ignite the
        DCPU.

        This should return `True` if the interrupt was queued successfully,
        and `False` if it was dropped (and is guaranteed to never trigger).

        :param message: The interrupt message that would have been enqueued.
        """
        self.ignite()
        return False

    def trigger_interrupt(self):
        """
        Retrieves an interrupt from the queue and triggers it.
        When an interrupt is delivered, it will:

        * Enable interrupt queueing
        * Push PC and A to the stack
        * Set A to the interrupt message
        * Jump to IA

        This will return `INT_QUEUE_ON`, `INT_QUEUE_EMPTY`, `INT_NO_HANDLER`,
        or `INT_DELIVERED`, depending on what happened.
        """
        if self.int_queue_enabled:
            return INT_QUEUE_ON

        if len(self.int_queue) == 0:
            return INT_QUEUE_EMPTY

        message = self.int_queue.popleft()

        if self.ia != 0:
            # Block interrupt queueing
            self.int_queue_enabled = True
            # Push PC and A to the stack
            self.push(self.pc)
            self.push(self.registers[A])
            # Set A to the interrupt message
            self.registers[A] = True
            # Jump to IA
            self.pc = self.ia

            return INT_DELIVERED
        else:
            return INT_NO_HANDLER


    ### DATA MANAGEMENT ###

    def load(self, address):
        """
        Loads a value from an address in the DCPU.

        :param address: An `Address` where a value is stored.
        """
        if isinstance(address, Register):
            return self.registers[address.register]
        elif isinstance(address, RegisterIndirect):
            return self.memory[self.registers[address.register]]
        elif isinstance(address, RegisterIndirectDisplaced):
            offset = self.registers[address.register] + address.displacement
            return self.memory[offset & WORD_MASK]

        elif address is PUSHPOP:
            return self.pop(value)
        elif address is PEEK:
            return self.memory[self.sp]

        elif address is SP:
            return self.sp
        elif address is PC:
            return self.pc
        elif address is EX:
            return self.ex

        elif isinstance(address, Displacement):
            return self.memory[address.address]
        elif isinstance(address, Immediate):
            return address.value

        else:
            raise TypeError("Invalid address type %r" % type(address))

    def store(self, address, value):
        """
        Stores a value at an address in the DCPU.

        :param address: An `Address` where the value will be stored.
        :param value: The value to store there.
        """
        value = value & WORD_MASK

        if isinstance(address, Register):
            self.registers[address.register] = value
        elif isinstance(address, RegisterIndirect):
            self.memory[self.registers[address.register]] = value
        elif isinstance(address, RegisterIndirectDisplaced):
            offset = self.registers[address.register] + address.displacement
            self.memory[offset & WORD_MASK] = value

        elif address is PUSHPOP:
            self.push(value)
        elif address is PEEK:
            self.memory[self.sp] = value

        elif address is SP:
            self.sp = value
        elif address is PC:
            self.pc = value
        elif address is EX:
            self.ex = value

        elif isinstance(address, Displacement):
            self.memory[address.displacement] = value
        elif isinstance(address, Immediate):
            pass

        else:
            raise TypeError("Invalid address type %r" % type(address))

    def push(self, value):
        """
        Pushes a value onto the stack maintained in the DCPU's memory.
        """
        self.sp = (self.sp - 2) & WORD_MASK
        self.memory[self.sp] = value

    def pop(self):
        """
        Pops and returns a value from the stack maintained in the DCPU's
        memory.
        """
        value = self.memory[self.sp]
        self.sp = (self.sp + 2) & WORD_MASK
        return value


    ### BINARY INSTRUCTIONS ###

    def ex_arithmetic_opcode(backing):
        @wraps(backing)
        def opcode(self, inst, b, a):
            av = self.load(a)
            bv = self.load(b)

            cv, ex = backing(self, bv, av)
            self.store(b, cv)
            if b is not EX and ex is not None:
                self.ex = ex & WORD_MASK

            return inst.base_cost
        return opcode

    def arithmetic_opcode(backing):
        @wraps(backing)
        def opcode(self, inst, b, a):
            av = self.load(a)
            bv = self.load(b)

            self.store(b, backing(self, bv, av))
            return inst.base_cost
        return opcode

    def if_arithmetic_opcode(backing):
        @wraps(backing)
        def opcode(self, inst, b, a):
            av = self.load(a)
            bv = self.load(b)

            if backing(self, bv, av):
                return inst.base_cost
            else:
                return inst.base_cost + self.skip_instructions()
        return opcode

    def SET(self, inst, b, a):
        self.store(b, self.load(a))
        return inst.base_cost

    @ex_arithmetic_opcode
    def ADD(self, b, a):
        val = b + a
        return val, (1 if val > WORD_MAX else 0)

    @ex_arithmetic_opcode
    def SUB(self, b, a):
        val = b - a
        return val, (WORD_MAX if val < 0 else 0)

    @ex_arithmetic_opcode
    def MUL(self, b, a):
        val = b * a
        return val, val >> 16

    @ex_arithmetic_opcode
    def MLI(self, b, a):
        val = sign_word(a) * sign_word(b)
        return val, val >> 16

    @ex_arithmetic_opcode
    def DIV(self, b, a):
        if a == 0:
            return 0, 0
        else:
            return b // a, (b << 16) // a

    @ex_arithmetic_opcode
    def DVI(self, b, a):
        if a == 0:
            return 0, 0
        else:
            b = sign_word(b)
            a = sign_word(a)
            return b // a, (b << 16) // a

    @arithmetic_opcode
    def MOD(self, b, a):
        if a == 0:
            return 0
        else:
            return b % a

    @arithmetic_opcode
    def MDI(self, b, a):
        if a == 0:
            return 0
        else:
            return sign_word(b) % sign_word(a)

    @arithmetic_opcode
    def AND(self, b, a):
        return b & a

    @arithmetic_opcode
    def BOR(self, b, a):
        return b | a

    @arithmetic_opcode
    def XOR(self, b, a):
        return b ^ a

    @ex_arithmetic_opcode
    def SHR(self, b, a):
        return b >> a, sign_dword(b << 16) >> a

    @ex_arithmetic_opcode
    def ASR(self, b, a):
        return sign_word(b) >> a, (b << 16) >> a

    @ex_arithmetic_opcode
    def SHL(self, b, a):
        return b << a, sign_dword(b << a) >> 16

    @if_arithmetic_opcode
    def IFB(self, b, a):
        return b & a

    @if_arithmetic_opcode
    def IFC(self, b, a):
        return not b & a

    @if_arithmetic_opcode
    def IFE(self, b, a):
        return b == a

    @if_arithmetic_opcode
    def IFN(self, b, a):
        return b != a

    @if_arithmetic_opcode
    def IFG(self, b, a):
        return b > a

    @if_arithmetic_opcode
    def IFA(self, b, a):
        return sign_word(b) > sign_word(a)

    @if_arithmetic_opcode
    def IFL(self, b, a):
        return b < a

    @if_arithmetic_opcode
    def IFU(self, b, a):
        return sign_word(b) < sign_word(a)

    @ex_arithmetic_opcode
    def ADX(self, b, a):
        val = (b + a + self.ex) & DWORD_MASK
        return val, val >> 16

    @ex_arithmetic_opcode
    def ADX(self, b, a):
        val = (b - a + self.ex) & DWORD_MASK
        return val, val >> 16

    def STI(self, inst, b, a):
        self.store(b, self.load(a))
        self.registers[I] = (self.registers[I] + 1) & WORD_MASK
        self.registers[J] = (self.registers[J] + 1) & WORD_MASK
        return inst.base_cost

    def STD(self, inst, b, a):
        self.store(b, self.load(a))
        self.registers[I] = (self.registers[I] - 1) & WORD_MASK
        self.registers[J] = (self.registers[J] - 1) & WORD_MASK
        return inst.base_cost

    del arithmetic_opcode, if_arithmetic_opcode, ex_arithmetic_opcode


    ### SPECIAL INSTRUCTIONS ###

    def JSR(self, inst, a):
        self.push(self.pc)
        self.pc = self.load(a)
        return inst.base_cost

    def INT(self, inst, a):
        self.interrupt(self.load(a))
        return inst.base_cost

    def IAG(self, inst, a):
        self.store(a, self.ia)
        return inst.base_cost

    def IAS(self, inst, a):
        self.ia = self.load(a)
        return inst.base_cost

    def IAQ(self, inst, a):
        self.int_queue_enabled = bool(self.load(a))
        return inst.base_cost

    def HWN(self, inst, a):
        self.store(a, len(self.hardware))
        return inst.base_cost

    def HWQ(self, inst, a):
        return inst.base_cost

    def HWI(self, inst, a):
        hw = self.load(a)
        return inst.base_cost
