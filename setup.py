#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
setup.py for dcpucore
=====================
:copyright: (C) 2013, Matthew Frazier
:license:   Released under the MIT/X11 license, see LICENSE for details
"""
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

# Load various pieces of information
with open("README.rst") as fd:
    README = fd.read()

packages = [
    "dcpucore"
]

scripts = [
    "scripts/dcasm.py"
]


setup(
    name='dcpucore',
    version='0.1-dev',
    url='https://github.com/leafstorm/dcpucore',
    license='MIT/X11',
    description="An embeddable DCPU-16 emulator and assembler.",
    long_description=README,

    author='Matthew Frazier',
    author_email='leafstormrush@gmail.com',

    classifiers=[
        'Development Status :: 2 - Pre-Alpha',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: MIT License',
        'Operating System :: OS Independent',
        'Programming Language :: Assembly',
        'Programming Language :: Python',
        'Topic :: Software Development :: Assemblers',
        'Topic :: Software Development :: Libraries',
        'Topic :: System :: Emulators'
    ],

    packages=packages,
    scripts=scripts,
    zip_safe=False
)
