# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

from setuptools import setup

INSTALL_REQUIRES = [
    "requests>=2.0",
    "django",
]

setup(
    name="example-constants",
    version="1.0.0",
    install_requires=INSTALL_REQUIRES,
)
