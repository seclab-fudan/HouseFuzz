# build AFL and install it to /AFLplusplus_release
ARG AFL_TARGET=custom

FROM --platform=linux/amd64 haccs_fuzzing_dude:latest as dude_orig

# =============================================================================

FROM --platform=linux/amd64 haccs_fuzzing_dude:latest as dude_custom

RUN apt-get update
RUN apt-get install -y gcc-9
RUN apt-get install -y g++-9
RUN rm /usr/bin/gcc
RUN rm /usr/bin/g++
RUN ln -s /usr/bin/gcc-9 /usr/bin/gcc
RUN ln -s /usr/bin/g++-9 /usr/bin/g++

RUN apt-get install -y libjansson-dev libcap-dev

COPY . /HouseFuzz

RUN cd /HouseFuzz && cp -R include src qemu_mode fuzz_nvram GNUmakefile /AFLplusplus/

# COPY include src qemu_mode fuzz_nvram GNUmakefile /AFLplusplus/

RUN ls --recursive /AFLplusplus

ENV LDFLAGS "-ljansson -lcap"

# =============================================================================

FROM --platform=linux/amd64 dude_${AFL_TARGET} as afl_base

WORKDIR /AFLplusplus

RUN STATIC=1 make distrib

# build afl-qemu-trace for different architectures

RUN cd qemu_mode/qemuafl; NO_CHECKOUT=1 CPU_TARGET=x86_64 STATIC=1 ./build_qemu_support.sh
RUN mv qemu_mode/qemuafl/afl-qemu-trace afl-qemu-trace-x86_64
RUN cd qemu_mode/qemuafl; NO_CHECKOUT=1 CPU_TARGET=i386 STATIC=1 ./build_qemu_support.sh
RUN mv qemu_mode/qemuafl/afl-qemu-trace afl-qemu-trace-i386
RUN cd qemu_mode/qemuafl; NO_CHECKOUT=1 CPU_TARGET=mips STATIC=1 ./build_qemu_support.sh
RUN mv qemu_mode/qemuafl/afl-qemu-trace afl-qemu-trace-mips
RUN cd qemu_mode/qemuafl; NO_CHECKOUT=1 CPU_TARGET=mipsel STATIC=1 ./build_qemu_support.sh
RUN mv qemu_mode/qemuafl/afl-qemu-trace afl-qemu-trace-mipsel
RUN cd qemu_mode/qemuafl; NO_CHECKOUT=1 CPU_TARGET=arm STATIC=1 ./build_qemu_support.sh
RUN mv qemu_mode/qemuafl/afl-qemu-trace afl-qemu-trace-arm
RUN cd qemu_mode/qemuafl; NO_CHECKOUT=1 CPU_TARGET=armeb STATIC=1 ./build_qemu_support.sh
RUN mv qemu_mode/qemuafl/afl-qemu-trace afl-qemu-trace-armeb
RUN cd qemu_mode/qemuafl; NO_CHECKOUT=1 CPU_TARGET=aarch64 STATIC=1 ./build_qemu_support.sh
RUN mv qemu_mode/qemuafl/afl-qemu-trace afl-qemu-trace-aarch64

RUN mkdir -p /AFLplusplus_release; PREFIX=/AFLplusplus_release STATIC=1 make install

# =============================================================================

# FROM --platform=linux/amd64 afl_base as afl_grammar

# ENV DEBIAN_FRONTEND=noninteractive

# RUN apt install -y valgrind uuid-dev default-jre python3
# RUN wget https://www.antlr.org/download/antlr-4.8-complete.jar -O /usr/local/lib/antlr-4.8-complete.jar

# COPY GrammarMutator/ /AFLplusplus/GrammarMutator/
# RUN cd GrammarMutator && \
#     for grammar in $(http json_no_ws); do \
#         mkdir -p build_http && \
#         cmake \
#             -DCMAKE_INSTALL_PREFIX:PATH \
#             -DANTLR_JAR_LOCATION=/usr/local/lib/antlr-4.8-complete.jar \
#             -DGRAMMAR_FILE=$(realpath ../grammars/${grammar}.json) \
#             -DGRAMMAR_FILENAME=${grammar} \
#             .. \
#     done

CMD /bin/bash
