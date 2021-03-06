# -*- coding: utf-8 -*-
"""
dcpucore.words
==============
Utilities for manipulating data at the bit level.

:copyright: (C) 2013 Matthew Frazier
:license:   MIT/X11 -- see the LICENSE file for details
"""
import array

for candidate in 'HILB':
    test = array.array(candidate)
    try:
        test.append(0xFFFF)
    except OverflowError:
        continue
    try:
        test.append(0x10000)
    except OverflowError:
        pass
    else:
        continue

    #: This is the :mod:`array` typecode that represents a DCPU word.
    #: (On most machines, it will be ``H``: unsigned short.)
    WORD_ARRAY = candidate
    break
else:
    raise SystemError("This system does not have a type for 0..0xFFFF")

del candidate, test


#: This mask can be used to strip off anything that's not a word.
#: Conveniently, it will also flip a negative number to its
#: twos-complement representation.
WORD_MASK = 0xFFFF

#: The minimum possible value of a DCPU-16 word.
WORD_MIN = 0

#: The maximum possible value of a DCPU-16 word.
WORD_MAX = 0xFFFF


#: This mask can be used to strip off anything that's not a double word.
#: Conveniently, it will also flip a negative number to its
#: twos-complement representation.
DWORD_MASK = 0xFFFFFFFF


def sign_word(word):
    """
    Takes an unsigned word and converts it into a signed word.
    (Words between 0 and 0x7FFF will be returned as is, 0x8000 to 0xFFFF
    will be converted to their negative version.)

    This function will NOT behave properly on words outside the range
    0x0000 to 0xFFFF.

    :param word: The unsigned word to convert.
    """
    return -(0x10000 - word) if word > 0x7FFF else word


def sign_dword(dword):
    """
    Takes an unsigned double word and converts it into a signed word.
    (Words between 0 and 0x7FFFFFFF will be returned as is,
    0x80000000 to 0xFFFFFFFF will be converted to their negative version.)

    This function will NOT behave properly on words outside the range
    0x00000000 to 0xFFFFFFFF.

    :param dword: The unsigned double word to convert.
    """
    return -(0x100000000 - dword) if dword > 0x7FFFFFFF else dword
