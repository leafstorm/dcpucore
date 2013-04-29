# -*- coding: utf-8 -*-
"""
dcasm.py
========
A command line interface for the dcpucore assembler.

Usage:
    dcasm.py [options] [<filename> [<output_filename>]]
    dcasm.py (-h | --help)

If <filename> or <output_filename> is omitted, standard input or output
will be used as appropriate.

Options:
    -B, --big-endian        Output in big-endian format.
    -L, --little-endian     Output in little-endian format (default).
    -D, --dat               Output as a series of DAT directives
                            (for final assembly later).

    -p, --parse             Don't assemble, just parse the instruction
                            stream.
    -1, --pass-1            Print the instruction stream after the first
                            assembler pass (equate resolution/optimization).
    -2, --pass-2            Print the instruction stream after the second
                            assembler pass (final label resolution).

    -d, --debug             Write parser debug messages to stderr and
                            generate a PLY parser.out file.

:copyright: (C) 2013 Matthew Frazier
:license:   MIT/X11 -- see the LICENSE file for details
"""
import dcpucore.assembler
import sys
from docopt import docopt

def error(message, code=1):
    print >>sys.stderr, message
    print >>sys.stderr, "(use -h or --help for help)"
    sys.exit(code)


options = docopt(__doc__)

parser = dcpucore.assembler.AssemblyParser(yacc_debug=options['--debug'])

if options['<filename>']:
    with open(options['<filename>']) as fd:
        source = fd.read()
else:
    source = sys.stdin.read()

instructions = parser.parse(source)

if options['<output_filename>']:
    output = open(options['<output_filename>'], 'w')
else:
    output = sys.stdout

if options['--parse']:
    for inst in instructions:
        print >>output, inst
else:
    program = dcpucore.assembler.Program(instructions)
    if options['--pass-1']:
        for inst in program.instructions:
            print >>output, "0x%04x: %s" % (inst.offset, inst)
    else:
        assembled = program.assemble()

        if options['--pass-2']:
            for inst in program.instructions:
                print >>output, "0x%04x: %s" % (inst.offset, inst)
        elif options['--dat']:
            for n in range(0, len(assembled), 8):
                print >>output, ("DAT " +
                    ", ".join("0x%04x" % x for x in assembled[n:n + 8])
                )
        else:
            if options['--big-endian'] and options['--little-endian']:
                error("Conflicting endianness requirements", 16)
            elif options['--big-endian']:
                if sys.byteorder != 'big':
                    assembled.byteswap()
            else:
                if sys.byteorder != 'little':
                    assembled.byteswap()

            assembled.tofile(output)
