# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

from setuptools import setup

with open("requirements.txt") as f:
    install_requires = f.read().splitlines()

setup(
    name="example-dynamic",
    version="1.0.0",
    install_requires=install_requires,
)
