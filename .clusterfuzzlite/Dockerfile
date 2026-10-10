# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

FROM gcr.io/oss-fuzz-base/base-builder-rust@sha256:9178c8abf83e7a82d02c1a9bf7b2f564320f669f7a1cec512ae9a8c4ea078427
COPY . $SRC/verilyze
WORKDIR $SRC/verilyze
COPY .clusterfuzzlite/build.sh $SRC/
