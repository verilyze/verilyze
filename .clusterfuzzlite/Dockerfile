# SPDX-FileCopyrightText: 2026 Travis Post <post.travis@gmail.com>
#
# SPDX-License-Identifier: GPL-3.0-or-later

FROM gcr.io/oss-fuzz-base/base-builder-rust@sha256:73be59e48262b7243f815f1c981a6e753e95e4b13e4d085cc9fc06bd79d42daa
COPY . $SRC/verilyze
WORKDIR $SRC/verilyze
COPY .clusterfuzzlite/build.sh $SRC/
