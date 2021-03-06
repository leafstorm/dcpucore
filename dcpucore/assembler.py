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
from .code import (DCPU_17, resolve_symbol, AssemblyError,
                   BinaryInstruction, SpecialInstruction,
                   Register, RegisterIndirect, RegisterIndirectDisplaced,
                   Displacement, Immediate, QuickImmediate,
                   PUSHPOP, PEEK, Pick, SP, PC, EX)
from .errors import (AssemblyError, AssemblySyntaxError, AssemblySymbolError,
                     SourceReference)
from .words import WORD_ARRAY, WORD_MASK

class Program(object):
    """
    A program represents an instruction stream in the process of being
    assembled. It operates in two passes:

    * In the first pass, any symbols that have already been assigned values
      are resolved. The instruction is optimized if possible, and appended
      to the instruction stream.
    * In the second pass, any remaining symbols are resolved. No optimization
      takes place during this pass, to prevent the offsets from changing.

    :param instructions: Any initial instructions to append to the instruction
                         stream.
    """
    def __init__(self, instructions=()):
        self.instructions = []
        self.source = None
        self.offset = 0
        self.symbols = {}

        if instructions:
            self.add(instructions)

    def add(self, instructions):
        """
        Adds instructions to the instruction stream, and runs the first pass
        of assembly on them. Calling `add` multiple times will place each
        instruction sequence one after another.

        :param instructions: The instructions to add and assemble.
        """
        for inst in instructions:
            if isinstance(inst, Origin):
                self.offset = inst.offset
            elif isinstance(inst, Label):
                inst.offset = self.offset
                self.symbols[inst.name] = inst.offset
            elif isinstance(inst, Equate):
                inst.offset = self.offset
                inst.resolve(self.symbols, True)
                self.symbols[inst.name] = inst.value
            else:
                inst.resolve(self.symbols, False)
                if hasattr(inst, 'optimize'):
                    inst = inst.optimize()

                inst.offset = self.offset

            self.offset += inst.size
            self.instructions.append(inst)

    def assemble(self):
        """
        Runs the second assembly pass on the instructions in this program,
        and returns a word array with the assembled code.
        """
        result = array.array(WORD_ARRAY)
        for inst in self.instructions:
            inst.resolve(self.symbols, True)
            result.extend(inst.assemble())
        return result


class Label(object):
    """
    Marks a point in an instruction stream that other instructions can
    refer to.

    :param name: The symbol's name.
    :param offset: A specific offset to used, if it can't be determined
                   automatically.
    :param source: The location where the label was defined.
    """
    def __init__(self, name, offset=None, source=None):
        self.name = name
        self.size = 0
        self.is_resolved = True
        self.offset = offset
        self.source = source

    def __str__(self):
        return ":%s" % self.name

    def copy(self):
        return self

    def resolve(self, symbols, require=False):
        pass

    def assemble(self):
        return []


class Equate(object):
    """
    Defines a symbol with a specific value (used similarly to a label).

    :param name: The symbol's name.
    :param value: The symbol's value.
    :param source: The location where the equate was defined.
    """
    def __init__(self, name, value, source=None):
        self.name = name
        self.size = 0
        self.offset = None
        self.value = value
        self.source = source

    def __str__(self):
        return ":%s equ %s" % self.value

    def copy(self):
        return Equate(self.name, self.value, self.source)

    @property
    def is_resolved(self):
        return not isinstance(self.value, basestring)

    def resolve(self, symbols, require=False):
        self.value = resolve_symbol(self.value, symbols, require, self.source)

    def assemble(self):
        return []


class Origin(object):
    """
    Resets the current offset to a given value. (This does not actually move
    the code -- the DCPU must take care of moving any code necessary.)

    :param offset: The new offset to generate code for.
    :param source: The location where the equate was defined.
    """
    def __init__(self, offset, source=None):
        self.size = 0
        self.is_resolved = True
        self.offset = offset
        self.source = source

    def __str__(self):
        return ".ORG 0x%04x" % self.offset

    def copy(self):
        return self

    def resolve(self, symbols, require=False):
        pass

    def assemble(self):
        return []


class Data(object):
    """
    Represents a block of data in an instruction stream.

    :param data: A tuple of words (either actual integers or symbols).
    :param source: The location where the equate was defined.
    """
    def __init__(self, data, source=None):
        self.data = data
        self.offset = None
        self.size = len(self.data)
        self.source = source

    def __str__(self):
        return "DAT " + ", ".join(str(x) for x in self.data)

    def copy(self):
        return Data(self.data, self.source)

    @property
    def is_resolved(self):
        return not any(isinstance(d, basestring) for d in self.data)

    def resolve(self, symbols, require=False):
        self.data = tuple(
            resolve_symbol(d, symbols, require, self.source)
            for d in self.data
        )

    def assemble(self):
        data = array.array(WORD_ARRAY)
        data.extend(self.data)
        return data


class AssemblyLexer(object):
    """
    A lexer for DCPU-16 assembly language. Few details of the language are
    hard-coded -- the interpretation of many tokens is based on the
    instruction set in use.

    :param instruction_set: The instruction set this lexer should use.
    :param single: If `False` (the default), the start rule will be
                   "one or more instructions." If `True`, the start rule
                   will be "one instruction."
    :param keywords: These identifiers will be parsed as a specific token
                     type, instead of as a generic `ID` token. (If they
                     start with ``.``, it will be in the form ``DOT_WORD``.)
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

        self.filenames = []

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

    def file_start(self, filename):
        self.filenames.append(filename)

    def file_complete(self, filename):
        if self.filenames[-1] != filename:
            raise Exception("Completed file %r is not current file %r!" %
                            (filename, self.filenames[-1]))
        self.filenames.pop()

    def get_source(self, t):
        return SourceReference(self.filenames[-1] if self.filenames else None,
                               t.lineno)

    def t_error(self, t):
        raise AssemblySyntaxError('Unexpected character %r' % t.value[0],
                                  self.get_source(t))


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
    :param yacc_debug: If `True`, PLY will generate rather annoying debugging
                       output.
    """
    def __init__(self, instruction_set=DCPU_17, single=False,
                 yacc_debug=False):
        self.isa = instruction_set

        self.keywords = set()
        for name, item in inspect.getmembers(self):
            if inspect.ismethod(item) and getattr(item, 'asm_keywords', ()):
                self.keywords.update(item.asm_keywords)

        self.lexer = self.create_lexer(yacc_debug)
        self.tokens = self.lexer.tokens
        self.start = 'instruction' if single is True else 'instructions'

        self.filenames = []
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
        if filename:
            self.file_start(filename)
            inst = self.parser.parse(source, lexer=self.lexer.lexer)
            self.file_complete(filename)
            return inst
        else:
            return self.parser.parse(source, lexer=self.lexer.lexer)


    def file_start(self, filename):
        self.filenames.append(filename)
        self.lexer.file_start(filename)

    def file_complete(self, filename):
        if self.filenames[-1] != filename:
            raise Exception("Completed file %r is not current file %r!" %
                            (filename, self.filenames[-1]))
        self.filenames.pop()
        self.lexer.file_complete(filename)

    def get_source(self, p, n):
        return SourceReference(self.filenames[-1] if self.filenames else None,
                               p.lineno(n))


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
        t[0] = Data(t[2], self.get_source(t, 1))

    @keyword('.ORG')
    def p_instruction_org(self, t):
        'instruction : DOT_ORG number_literal'
        t[0] = Origin(t[2], self.get_source(t, 1))

    @keyword('EQU')
    def p_instruction_equ(self, t):
        'instruction : LABEL EQU number'
        t[0] = Equate(t[1], t[3], self.get_source(t, 1))

    def p_instruction_label(self, t):
        'instruction : LABEL'
        t[0] = Label(t[1], self.get_source(t, 1))


    def p_instruction_binary(self, t):
        'instruction : BINARY_OP address address'
        t[0] = BinaryInstruction(self.isa.by_mnemonic[t[1]], t[2], t[3],
                                 self.get_source(t, 1))

    def p_instruction_special(self, t):
        'instruction : SPECIAL_OP address'
        a = t[2]
        if (isinstance(a, Immediate) and isinstance(a.value, int) and
                    a.value >= -1 and a.value <= 30):
            a = QuickImmediate(a.value)
        t[0] = SpecialInstruction(self.isa.by_mnemonic[t[1]], a,
                                  self.get_source(t, 1))


    def p_address_register(self, t):
        'address : GP_REG'
        t[0] = Register(t[1], self.get_source(t, 1))

    def p_address_register_indirect(self, t):
        'address : LBRACK GP_REG RBRACK'
        t[0] = RegisterIndirect(t[2], self.get_source(t, 2))

    def p_address_register_indirect_displaced_l(self, t):
        'address : LBRACK GP_REG PLUS number RBRACK'
        t[0] = RegisterIndirectDisplaced(t[2], t[4], self.get_source(t, 4))

    def p_address_register_indirect_displaced_r(self, t):
        'address : LBRACK number PLUS GP_REG RBRACK'
        t[0] = RegisterIndirectDisplaced(t[4], t[2], self.get_source(t, 2))

    def p_address_push_pop(self, t):
        """
        address : PUSH
        address : LBRACK DEC SP RBRACK
        address : POP
        address : LBRACK SP INC RBRACK
        """
        t[0] = PUSHPOP

    def p_address_peek(self, t):
        """
        address : LBRACK SP RBRACK
        address : PEEK
        """
        t[0] = PEEK

    def p_address_pick_l(self, t):
        'address : LBRACK SP PLUS number RBRACK'
        t[0] = Pick(t[4], self.get_source(t, 4))

    def p_address_pick_r(self, t):
        'address : LBRACK number PLUS SP RBRACK'
        t[0] = Pick(t[2], self.get_source(t, 2))

    def p_address_pick_k(self, t):
        'address : PICK number'
        t[0] = Pick(t[2], self.get_source(t, 2))

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
        t[0] = Displacement(t[2], self.get_source(t, 2))

    def p_address_immediate(self, t):
        'address : number'
        t[0] = Immediate(t[1], self.get_source(t, 1))


    def p_number(self, t):
        '''number : DECIMAL
                  | HEX
                  | OCT
                  | ID
                  | CHAR'''
        t[0] = t[1]
        t.set_lineno(0, t.lineno(1))

    def p_number_literal(self, t):
        '''number_literal : DECIMAL
                          | HEX
                          | OCT
                          | CHAR'''
        t[0] = t[1]
        t.set_lineno(0, t.lineno(1))


    def p_error(self, t):
        filename = self.filenames[-1] if self.filenames else None
        if t is None:
            src = SourceReference(filename, None)
            raise AssemblySyntaxError('Input ended too soon', src)
        else:
            src = SourceReference(filename, t.lineno)
            raise AssemblySyntaxError('Misplaced token: %r' % t.value, src)
