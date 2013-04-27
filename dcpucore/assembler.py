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
import inspect
import ply.lex as lex
import ply.yacc as yacc
from .code import (DCPU_17, resolve_symbol,
                   BinaryInstruction, SpecialInstruction,
                   Register, RegisterIndirect, RegisterIndirectDisplaced,
                   Displacement, Immediate, QuickImmediate,
                   PUSHPOP, PEEK, Pick, SP, PC, EX)
from .words import WORD_ARRAY, WORD_MASK

class AssemblyLexer(object):
    """
    A lexer for DCPU-16 assembly language. Few details of the language are
    hard-coded -- the interpretation of many tokens is based on the
    instruction set in use.

    :param instruction_set: The instruction set this lexer should use.
    :param single: If `False` (the default), the start rule will be
                   "one or more instructions." If `True`, the start rule
                   will be "one instruction."
    :param suppress_keywords: A quick way to disable assembler features
                              you don't want. This is a list of keywords
                              to not lex as keywords, which will result
                              in the corresponding directives not being
                              parsed. (For example, to disable ``.ORG``,
                              you could pass ``suppress_keywords=['.ORG']``.)
    :param lex_debug: If `True`, PLY will generate rather annoying debugging
                      output.
    """
    def __init__(self, instruction_set=DCPU_17, keywords=(), lex_debug=False):
        self.isa = instruction_set
        self.keywords = keywords

        self.tokens = list(self.base_tokens)
        self.tokens.extend('DOT_' + kw[1:] if kw[0] == '.' else kw
                           for kw in self.keywords)
        self.tokens.extend(self.isa.SPECIAL_REGISTERS)
        self.tokens.extend(self.isa.SPECIAL_OPERATIONS)
        self.tokens.extend(t.upper() + '_OP' for t in self.isa.opcodes)
        self.lexer = lex.lex(module=self, debug=lex_debug)

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
        'GP_REG'
    )

    t_ignore = ' \t\r,'
    t_ignore_COMMENT = r';.*'

    t_INC = r'\+\+'
    t_DEC = r'\-\-'
    t_LBRACK = r'\['
    t_RBRACK = r'\]'
    t_PLUS = r'\+'

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
            t.type = 'DOT_' + upper[1:] if upper[0] == '.' else upper
            t.value = upper
        else:
            t.type = 'ID'
        return t

    def t_error(self, t):
        raise Exception('Unrecognized token on line %d: %s' %
                        (t.lineno, t.value))


class Program(object):
    def __init__(self, instructions=()):
        self.instructions = []
        self.source = None
        self.offset = 0
        self.symbols = {}

        if instructions:
            self.add(instructions)

    def add(self, instructions):
        for inst in instructions:
            if isinstance(inst, Origin):
                self.offset = inst.offset
            elif inst.offset is None:
                inst.offset = self.offset
                self.offset += inst.size

            if isinstance(inst, Label):
                self.symbols[inst.name] = inst.offset
            elif isinstance(inst, Equate):
                self.symbols[inst.name] = inst.value

            self.instructions.append(inst)

    def assemble(self):
        result = array.array(WORD_ARRAY)
        for inst in self.instructions:
            result.extend(inst.assemble(self.symbols))
        return result


class Label(object):
    def __init__(self, name, offset=None):
        self.name = name
        self.size = 0
        self.offset = offset

    def __str__(self):
        return ":%s" % self.name

    def assemble(self, symbols=None):
        return []


class Equate(object):
    def __init__(self, name, value=None):
        self.name = name
        self.size = 0
        self.offset = None
        self.value = value

    def __str__(self):
        return ":%s equ %s" % self.value

    def assemble(self, symbols=None):
        return []


class Origin(object):
    def __init__(self, offset):
        self.size = 0
        self.offset = offset

    def __str__(self):
        return ".ORG 0x%04x" % self.offset

    def assemble(self, symbols=None):
        return []


class Data(object):
    def __init__(self, data):
        self.data = data
        self.offset = None
        self.size = len(self.data)

    def __str__(self):
        return "DAT " + ", ".join(str(x) for x in self.data)

    def assemble(self, symbols=None):
        data = array.array(WORD_ARRAY)
        data.extend(resolve_symbol(sym, symbols) for sym in self.data)
        return data


def keyword(*words):
    """
    A decorator that associates specific keywords with a parse rule
    on an instance of `AssemblyParser`. This will result in these
    words automatically being treated as keywords by the lexer.

    (Behavior is undefined if a keyword on the parser conflicts with a
    reserved word loaded from the instruction set.)
    """
    def decorate(fn):
        fn.asm_keywords = words
        return fn

    return decorate


class AssemblyParser(object):
    """
    A parser for DCPU-16 assembly language. You can customize the language
    either by using the instruction set, or by subclassing and
    adding/overriding PLY parse methods.

    :param instruction_set: The instruction set this parser should use.
    :param single: If `False` (the default), the start rule will be
                   "one or more instructions." If `True`, the start rule
                   will be "one instruction."
    :param suppress_keywords: A quick way to disable assembler features
                              you don't want. This is a list of keywords
                              to not lex as keywords, which will result
                              in the corresponding directives not being
                              parsed. (For example, to disable ``.ORG``,
                              you could pass ``suppress_keywords=['.ORG']``.)
    :param yacc_debug: If `True`, PLY will generate rather annoying debugging
                       output.
    """
    def __init__(self, instruction_set=DCPU_17, single=False,
                 suppress_keywords=(), yacc_debug=False):
        self.isa = instruction_set

        self.keywords = set()
        for name, item in inspect.getmembers(self):
            if inspect.ismethod(item) and getattr(item, 'asm_keywords', ()):
                self.keywords.update(item.asm_keywords)
        for keyword in suppress_keywords:
            self.keywords.discard(keyword)

        self.lexer = self.create_lexer(yacc_debug)
        self.tokens = self.lexer.tokens
        self.start = 'instruction' if single is True else 'instructions'

        self.parser = yacc.yacc(module=self, debug=yacc_debug,
                                write_tables=False)

    def create_lexer(self, lex_debug=False):
        """
        Creates a PLY lexer instance for this parser.

        :param lex_debug: If `True`, PLY will generate rather annoying
                          debugging output.
        """
        return AssemblyLexer(self.isa, self.keywords, lex_debug=lex_debug)

    def parse(self, source, filename=None):
        """
        Parses assembly code into instruction objects.

        :param source: The assembly source to parse.
        :param filename: The name of the file it was read from.
        """
        return self.parser.parse(source, lexer=self.lexer.lexer)

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

    @keyword('DAT')
    def p_instruction_data(self, t):
        'instruction : DAT data'
        t[0] = Data(t[2])

    @keyword('.ORG')
    def p_instruction_org(self, t):
        'instruction : DOT_ORG number_literal'
        t[0] = Origin(t[2])

    @keyword('EQU')
    def p_instruction_equ(self, t):
        'instruction : LABEL EQU number_literal'
        t[0] = Equate(t[1], t[3])

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

    def p_number_literal(self, t):
        '''number_literal : DECIMAL
                          | HEX
                          | OCT
                          | CHAR'''
        t[0] = t[1]


    def p_error(self, t):
        raise Exception('Invalid token on line %d: %s' % (t.lineno, t.value))
