# SPDX-License-Identifier: GPL-3.0-or-later

from Cython.Build import cythonize
from setuptools import setup

setup(
    ext_modules=cythonize("dvm.pyx"),
)
