# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

from setuptools import setup

setup(
    name="example-binop",
    version="1.0.0",
    install_requires=["a"] + ["b"],
)
