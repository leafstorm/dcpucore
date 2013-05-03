# -*- coding: utf-8 -*-
"""
dcpucore.errors
===============
This contains base code for handing errors that occur during assembly.

:copyright: (C) 2013 Matthew Frazier
:license:   MIT/X11 -- see the LICENSE file for details
"""

class SourceReference(object):
    """
    This holds a reference to a location in an input file.

    :param filename: The name of the file (or other input source).
    :param line:     The 1-based line number, if a specific line is known.
    :param col:      The 1-based column number, if a specific column is known.
    """
    __slots__ = ('filename', 'line', 'col')

    def __init__(self, filename=None, line=None, col=None):
        self.filename = filename
        self.line = line
        self.col = col

    def __nonzero__(self):
        return (self.filename is not None or self.line is not None or
                self.col is not None)

    def __str__(self):
        if self.filename:
            if self.line and self.col:
                return " at {} line {}, col {}".format(
                    self.filename, self.line, self.col
                )
            elif self.line:
                return " at {} line {}".format(self.filename, self.line)
            elif self.col:
                return " at {} col {}".format(self.filename, self.col)
            else:
                return " in {}".format(self.filename)
        else:
            if self.line and self.col:
                return " at line {}, col {}".format(self.line, self.col)
            elif self.line:
                return " at line {}".format(self.line)
            elif self.col:
                return " at col {}".format(self.col)
            else:
                return ""


class DCPUError(Exception):
    """
    The base class for all DCPU-related errors that aren't technically errors
    on the Python side.
    """


class AssemblyError(DCPUError):
    """
    An error that occurred during the parsing/assembly phase.

    :param message: A message describing this error.
    :param source:  The source of this error, if known.
    """
    def __init__(self, message, source=None):
        self.message = message
        self.source = source

    def __str__(self):
        if self.source:
            return self.message + str(self.source)
        else:
            return self.message


class AssemblySymbolError(AssemblyError):
    """
    Indicates that the assembly referred to an undefined symbol.

    :param symbol:  The symbol that wasn't defined.
    :param source:  The source of this error, if known.
    """
    def __init__(self, symbol, source):
        self.symbol = symbol
        self.source = source

    @property
    def message(self):
        return "Undefined symbol '{}'".format(self.symbol)


class AssemblySyntaxError(AssemblyError):
    """
    Indicates that the assembly language syntax was incorrect.
    """
