# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

FROM gcr.io/oss-fuzz-base/base-builder-rust@sha256:47bbe5147371187603326af515511e6bad2dcd6e6912fa42c66fb161b5bd770b
COPY . $SRC/verilyze
WORKDIR $SRC/verilyze
COPY .clusterfuzzlite/build.sh $SRC/
