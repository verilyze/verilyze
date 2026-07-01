# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

from setuptools import setup

setup(
    name="example-extras",
    version="1.0.0",
    install_requires=["requests>=2.0"],
    extras_require={
        "dev": ["pytest>=7.0", "black"],
        "docs": ["sphinx>=5.0"],
    },
    tests_require=["pytest-cov>=4.0"],
)
