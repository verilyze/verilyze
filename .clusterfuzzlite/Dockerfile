# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

FROM gcr.io/oss-fuzz-base/base-builder-rust@sha256:30133d6ddfd9d2649c2821e3ee928e399f17b17dd04697f553bcda403e4f58b2
COPY . $SRC/verilyze
WORKDIR $SRC/verilyze
COPY .clusterfuzzlite/build.sh $SRC/
