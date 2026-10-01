# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

FROM gcr.io/oss-fuzz-base/base-builder-rust@sha256:2d04d0440106bd33c8fa7b6fa7c6562f0c40c726603d2223c2b341c65cd4cae8
COPY . $SRC/verilyze
WORKDIR $SRC/verilyze
COPY .clusterfuzzlite/build.sh $SRC/
