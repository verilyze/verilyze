# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Example package using classic setuptools import style."""
from setuptools import setup

setup(
    name="example-classic",
    version="1.0.0",
    description="A sample package for vlz fixture testing",
    install_requires=[
        "requests==2.31.0",
        "django>=4.2",
    ],
)
