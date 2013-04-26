# -*- coding: utf-8 -*-
"""
dcpucore.assembler
==================
A DCPU assembler.

The code was lovingly ripped off from Michael Fogleman's DCPU assembler
(<https://github.com/fogleman/DCPU-16/blob/master/app/assembler.py>),
which is released under a MIT license.

:copyright: (C) 2013 Matthew Frazier
:license:   MIT/X11 -- see the LICENSE file for details
"""
import array
import ply.lex as lex
import ply.yacc as yacc
from .code import (DCPU_17, resolve_symbol,
                   BinaryInstruction, SpecialInstruction,
                   Register, RegisterIndirect, RegisterIndirectDisplaced,
                   Displacement, Immediate, QuickImmediate,
                   PUSHPOP, PEEK, Pick, SP, PC, EX)
from .words import WORD_ARRAY, WORD_MASK

class AssemblyLexer(object):
    def __init__(self, instruction_set=DCPU_17):
        self.isa = instruction_set
        self.tokens = list(self.base_tokens)
        self.tokens.extend(self.keywords)
        self.tokens.extend(self.isa.SPECIAL_REGISTERS)
        self.tokens.extend(self.isa.SPECIAL_OPERATIONS)
        self.tokens.extend(t.upper() + '_OP' for t in self.isa.opcodes)
        self.lexer = lex.lex(module=self)

    base_tokens = (
        'LBRACK',
        'RBRACK',
        'PLUS',
        'LABEL',
        'ID',
        'DECIMAL',
        'HEX',
        'OCT',
        'STRING',
        'CHAR',
        'INC',
        'DEC',
        'AT',
        'GP_REG'
    )

    keywords = frozenset(('DAT',))

    t_ignore = ' \t\r,'
    t_ignore_COMMENT = r';.*'

    t_INC = r'\+\+'
    t_DEC = r'\-\-'
    t_LBRACK = r'\['
    t_RBRACK = r'\]'
    t_PLUS = r'\+'
    t_AT = r'\@'

    def t_newline(self, t):
        r'\n+'
        t.lexer.lineno += len(t.value)

    def t_STRING(self, t):
        r'"[^"]*"'
        t.value = tuple(ord(x) for x in t.value[1:-1])
        return t

    def t_CHAR(self, t):
        r"'[^']'"
        t.value = ord(t.value[1])
        return t

    def t_HEX(self, t):
        r'\-?0x[a-fA-F0-9]+'
        t.value = int(t.value, 16) & WORD_MASK
        return t

    def t_OCT(self, t):
        r'\-?0\d+'
        t.value = int(t.value, 8) & WORD_MASK
        return t

    def t_DECIMAL(self, t):
        r'\-?\d+'
        t.value = int(t.value, 10) & WORD_MASK
        return t

    def t_LABEL(self, t):
        r':\.?[a-zA-Z_][a-zA-Z_0-9]*'
        t.value = t.value[1:]
        if t.value[0] == '.':
            t.value = '%s%s' % (t.lexer.label_prefix, t.value)
        else:
            t.lexer.label_prefix = t.value
        return t

    def t_ID(self, t):
        r'\.?[a-zA-Z_][a-zA-Z_0-9]*'
        upper = t.value.upper()
        if upper in self.isa.GENERAL_REGISTERS:
            t.type = 'GP_REG'
            t.value = self.isa.GENERAL_REGISTERS.index(upper)
        elif upper in self.isa.by_mnemonic:
            t.type = self.isa.by_mnemonic[upper].type.upper() + '_OP'
            t.value = upper
        elif (upper in self.keywords or upper in self.isa.SPECIAL_REGISTERS or
              upper in self.isa.SPECIAL_OPERATIONS):
            t.type = upper
            t.value = upper
        else:
            t.type = 'ID'
        return t

    def t_error(self, t):
        raise Exception('Unrecognized token on line %d: %s' %
                        (t.lineno, t.value))


class Program(object):
    def __init__(self, instructions):
        self.instructions = instructions
        self.source = None
        self.size = 0
        self.symbols = {}

        for inst in instructions:
            if inst.offset is None:
                inst.offset = self.size
                self.size += inst.size
            if isinstance(inst, Label):
                self.symbols[inst.name] = inst.offset

    def assemble(self):
        result = array.array(WORD_ARRAY)
        for inst in self.instructions:
            result.extend(inst.assemble(self.symbols))
        return result


class Label(object):
    def __init__(self, name, offset=None):
        self.name = name
        self.size = 0
        self.offset = self.size

    def __str__(self):
        return ":%s" % self.name

    def assemble(self, symbols=None):
        return []


class Data(object):
    def __init__(self, data):
        self.data = data
        self.offset = None
        self.size = len(self.data)

    def assemble(self, symbols=None):
        data = array.array(WORD_ARRAY)
        data.extend(resolve_symbol(sym, symbols) for sym in self.data)
        return data


class AssemblyParser(object):
    def __init__(self, instruction_set=DCPU_17):
        self.isa = instruction_set
        self.lexer = AssemblyLexer(instruction_set)
        self.tokens = self.lexer.tokens
        self.parser = yacc.yacc(module=self, debug=False, write_tables=False)

    def parse(self, source, filename=None):
        program = self.parser.parse(source, lexer=self.lexer.lexer)
        program.source = source
        return program

    start = 'program'

    def p_program(self, t):
        'program : instructions'
        t[0] = Program(t[1])

    def p_instructions(self, t):
        'instructions : instruction instructions'
        t[0] = (t[1],) + t[2]

    def p_instruction_tail(self, t):
        'instructions : instruction'
        t[0] = (t[1],)


    def p_data(self, t):
        '''
        data : number data
        data : STRING data
        data : number
        data : STRING
        '''
        arg = t[1] if isinstance(t[1], tuple) else (t[1],)
        if len(t) > 2:
            t[0] = arg + t[2]
        else:
            t[0] = arg

    def p_instruction_data(self, t):
        'instruction : DAT data'
        t[0] = Data(t[2])


    def p_instruction_label(self, t):
        'instruction : LABEL'
        t[0] = Label(t[1])


    def p_instruction_binary(self, t):
        'instruction : BINARY_OP address address'
        a = t[3]
        if (isinstance(a, Immediate) and isinstance(a.value, int) and
                    a.value >= -1 and a.value <= 30):
            a = QuickImmediate(a.value)
        t[0] = BinaryInstruction(self.isa.by_mnemonic[t[1]], t[2], a)

    def p_instruction_special(self, t):
        'instruction : SPECIAL_OP address'
        a = t[2]
        if (isinstance(a, Immediate) and isinstance(a.value, int) and
                    a.value >= -1 and a.value <= 30):
            a = QuickImmediate(a.value)
        t[0] = SpecialInstruction(self.isa.by_mnemonic[t[1]], a)


    def p_address_register(self, t):
        'address : GP_REG'
        t[0] = Register(t[1])

    def p_address_register_indirect(self, t):
        'address : LBRACK GP_REG RBRACK'
        t[0] = RegisterIndirect(t[2])

    def p_address_register_indirect_displaced_l(self, t):
        'address : LBRACK GP_REG PLUS number RBRACK'
        t[0] = RegisterIndirectDisplaced(t[2], t[4])

    def p_address_register_indirect_displaced_r(self, t):
        'address : LBRACK number PLUS GP_REG RBRACK'
        t[0] = RegisterIndirectDisplaced(t[4], t[2])

    def p_address_push_pop(self, t):
        """
        address : PUSH
        address : LBRACK DEC SP RBRACK
        address : POP
        address : LBRACK SP INC RBRACK
        """
        t[0] = PUSHPOP

    def p_address_peek(self, t):
        'address : LBRACK SP RBRACK'
        t[0] = PEEK

    def p_address_pick_l(self, t):
        'address : LBRACK SP PLUS number RBRACK'
        t[0] = Pick(t[4])

    def p_address_pick_r(self, t):
        'address : LBRACK number PLUS SP RBRACK'
        t[0] = Pick(t[2])

    def p_address_pick_k(self, t):
        'address : PICK number'
        t[0] = Pick(t[2])

    def p_address_sp(self, t):
        'address : SP'
        t[0] = SP

    def p_address_pc(self, t):
        'address : PC'
        t[0] = PC

    def p_address_ex(self, t):
        'address : EX'
        t[0] = EX

    def p_address_displacement(self, t):
        'address : LBRACK number RBRACK'
        t[0] = Displacement(t[2])

    def p_address_immediate(self, t):
        'address : number'
        t[0] = Immediate(t[1])


    def p_number(self, t):
        '''number : DECIMAL
                  | HEX
                  | OCT
                  | ID
                  | CHAR'''
        t[0] = t[1]


    def p_error(self, t):
        raise Exception('Invalid token on line %d: %s' % (t.lineno, t.value))
