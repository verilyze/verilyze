# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

"""Package using setuptools.setup module call."""
import setuptools

setuptools.setup(
    name="example-setuptools",
    version="0.2.0",
    install_requires=[
        "httpx>=0.20",
        "click==8.1.0",
    ],
)
