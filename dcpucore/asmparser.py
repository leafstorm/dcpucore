# -*- coding: utf-8 -*-
"""
dcpucore.asmparser
==================
A parser for DCPU assembly code. This is designed to work with
`dcupcore.assembler`.

:copyright: (C) 2013 Matthew Frazier
:license:   MIT/X11 -- see the LICENSE file for details
"""
import re

class AssemblyError(BaseException):
    """
    This represents an error that can occur while processing assembler code.

    :param detail: A message indicating what went wrong.
    :param filename: The filename where the error happened.
    :param lineno: The 1-based line number where the error happened.
    :param col: The 0-based column number where the error happened.
                (Yes, this is slightly inconsistent.)
    """
    def __init__(self, detail, filename=None, lineno=None, col=None):
        self.detail = detail
        self.filename = filename
        self.lineno = lineno
        self.col = col

    @property
    def location(self):
        """
        Returns a string describing the location where this error occurred:
        filename, line number, and column, where the appropriate information
        is provided.
        """
        if self.filename:
            if self.lineno and self.col:
                return ("%s (line %d, col %d)" %
                        (self.filename, self.lineno, self.col + 1))
            elif self.lineno:
                return "%s (line %d)" % (self.filename, self.lineno)
            else:
                return self.filename
        else:
            if self.lineno and self.col:
                return "line %d, col %d" % (self.lineno, self.col + 1)
            elif self.lineno:
                return "line %d" % self.lineno
            elif self.col:
                return "col %d" % (self.col + 1)
            else:
                return None

    def __str__(self):
        location = self.location
        if location is None:
            return self.detail
        else:
            return self.detail + " at " + location


class AssemblySyntaxError(AssemblyError):
    """
    This indicates an error that occurs while structurally parsing the
    assembly code. (This doesn't include semantic errors, like
    ``SET [A + X], "fish"`` -- just errors like misplaced characters.)
    """


SPACES = re.compile(r"\s*")

NAME_LEAD = r"[a-zA-Z_]"
NAME_TRAIL = r"[a-zA-Z0-9_]"

LABEL_DEF = re.compile(r":(%s%s*)" % (NAME_LEAD, NAME_TRAIL))

NAME = re.compile(r"%s%s*" % (NAME_LEAD, NAME_TRAIL))

COMMAND = re.compile(r"\.?%s%s*" % (NAME_LEAD, NAME_TRAIL))

HEX_INTEGER = re.compile(r"(-?)0x([0-9a-fA-F]+)")
BIN_INTEGER = re.compile(r"(-?)0b([01]+)")
OCT_INTEGER = re.compile(r"(-?)0o([0-7]+)")
DEC_INTEGER = re.compile(r"(-?)([0-9]+)")

INTEGERS = ((HEX_INTEGER, 16), (BIN_INTEGER, 2), (OCT_INTEGER, 8),
            (DEC_INTEGER, 10))

SQ_STRING = re.compile(r"'([^']*)'")
DQ_STRING = re.compile(r'"([^"]*)"')


class AssemblyParser(object):
    """
    This parses the syntax of DCPU-16 assembly language.
    """
    def skip_spaces(self, line, col):
        match = SPACES.match(line, col)
        return match.end()

    def at_end(self, line, col):
        return col == len(line) or line[col] == ';'

    def parse_program(self, program, filename=None):
        """
        Parses a program into assembly, and returns an abstract sytnax tree
        of sorts. This is a generator that generates tuples in the form::

            (lineno, (command, argument, argument, ...))

        Where `command` is an uppercase string, and `argument` is a string
        (for string arguments) or a tuple (for all others -- the first
        element is `True` for memory references and `False` for immediates,
        the following elements are the components of the sum).

        (Labels are the only special case -- labels generate directives
        that would look like ``.LABEL "foo"`` in actual code.)

        :param program: The program source code.
        :param filename: The name of the file this source was loaded from.
        """
        for lineno, line in enumerate(program.splitlines()):
            label, command = self.parse_line(line, filename, lineno + 1)
            if label is not None:
                yield lineno, ('.LABEL', label)
            if command is not None:
                yield lineno, command

    def parse_line(self, line, filename=None, lineno=None, col=0):
        label = None
        command = None
        arguments = []

        # Skip any leading spaces.
        col = self.skip_spaces(line, col)
        # Are we at the end?
        if self.at_end(line, col):
            return None, None

        # First off: does this line have a label definition?
        label, col = self.parse_label_def(line, col)
        if label:
            # If so, we need to skip and check for the end again.
            col = self.skip_spaces(line, col)
            if self.at_end(line, col):
                return label, None

        # Now, parse the command.
        command, col = self.parse_command(line, col)
        if not command and not self.at_end(line, col):
            raise AssemblySyntaxError("Expected a mnemonic or directive",
                                      filename, lineno, col)

        # Bail out early if it's a nullary command.
        col = self.skip_spaces(line, col)
        if self.at_end(line, col):
            return label, (command,)

        # Otherwise, parse its arguments.
        while True:
            argument, col = self.parse_argument(filename, lineno, line, col)
            arguments.append(argument)

            col = self.skip_spaces(line, col)
            if self.at_end(line, col):
                break
            elif line[col] != ',':
                raise AssemblySyntaxError("Expected a comma (,) to separate "
                                          "arguments", filename, lineno, col)
            col += 1
            col = self.skip_spaces(line, col)
            if self.at_end(line, col):
                raise AssemblySyntaxError("Expected an argument to follow "
                                          "the comma", filename, lineno, col)

        return label, (command,) + tuple(arguments)

    def parse_label_def(self, line, col):
        match = LABEL_DEF.match(line, col)
        if match:
            return match.group(1), match.end()
        else:
            return None, col

    def parse_command(self, line, col):
        match = COMMAND.match(line, col)
        if match:
            return match.group().upper(), match.end()
        else:
            return None, col

    def parse_argument(self, filename, lineno, line, col):
        if line[col] == '[':
            col += 1
            col = self.skip_spaces(line, col)
            primaries, col = self.parse_sum(filename, lineno, line, col)
            if self.at_end(line, col) or line[col] != ']':
                raise AssemblySyntaxError("Didn't close memory reference",
                                          filename, lineno, col)
            col += 1
            return (True,) + tuple(primaries), col
        elif line[col] == '"' or line[col] == "'":
            return self.parse_string(filename, lineno, line, col)
        else:
            primaries, col = self.parse_sum(filename, lineno, line, col)
            return (False,) + tuple(primaries), col

    def parse_string(self, filename, lineno, line, col):
        if line[col] == '"':
            match = DQ_STRING.match(line, col)
        elif line[col] == "'":
            match = SQ_STRING.match(line, col)
        else:
            return None, col

        if match:
            return match.group(1), match.end()
        else:
            raise AssemblySyntaxError("Malformed string literal",
                                      filename, lineno, col)

    def parse_sum(self, filename, lineno, line, col):
        primaries = []
        negate = False
        while True:
            primary, col = self.parse_primary(line, col)
            if primary is None:
                raise AssemblySyntaxError("Expected a register, name, or "
                                          "numeric literal",
                                          filename, lineno, col)
            if negate and isinstance(primary, int):
                primaries.append(-primary)
            elif negate:
                primaries.append('-' + primary)
            else:
                primaries.append(primary)

            col = self.skip_spaces(line, col)
            if self.at_end(line, col):
                return tuple(primaries), col
            if line[col] == '+':
                negate = False
                col = self.skip_spaces(line, col + 1)
            elif line[col] == '-':
                negate = True
                col = self.skip_spaces(line, col + 1)
            else:
                return tuple(primaries), col

    def parse_primary(self, line, col):
        for regex, base in INTEGERS:
            int_match = regex.match(line, col)
            if int_match:
                return (int(int_match.group(1) + int_match.group(2), base),
                        int_match.end())

        name_match = NAME.match(line, col)
        if name_match:
            return name_match.group(), name_match.end()

        return None, col
