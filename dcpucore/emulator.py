# -*- coding: utf-8 -*-
"""
dcpucore.emulator
=================
The actual DCPU emulator.

:copyright: (C) 2013 Matthew Frazier
:license:   MIT/X11 -- see the LICENSE file for details
"""
import array

class DCPURuntimeException(Exception):
    """
    This represents something unexpected happening during emulation.
    """


class Emulator(object):
    """
    This represents a DCPU-16.
    """
