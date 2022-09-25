# Singapore Polytechnic ITSP Final Year Project (Group 7) AY2022/23
# ARM Binary Reverse Engineering: Command Injection Vulnerability (FinjectRoute)
# Docker image build script

# Written by: Chua Chok Yang, Mr Peter Teoh

FROM alpine:3.14

ENV VERSION 10.1.4_PUBLIC
ENV GHIDRA_SHA 91556c77c7b00f376ca101a6026c0d079efbf24a35b09daaf80bda897318c1f1
ENV GHIDRA_URL https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.1.4_build/ghidra_10.1.4_PUBLIC_20220519.zip
ENV BINWALK_URL https://github.com/ReFirmLabs/binwalk/archive/refs/heads/master.zip


RUN apk update
RUN apk upgrade

RUN apk add --no-cache openjdk11 bash

RUN apk add --update --no-cache graphviz font-bitstream-type1 ghostscript-fonts ttf-freefont

RUN apk add jq gcc musl-dev py3-pip libart-lgpl-dev file nano gcompat libc6-compat freetype-dev python3-dev linux-headers libc-dev

RUN apk --update add libxml2-dev libxslt-dev libffi-dev gcc musl-dev libgcc openssl-dev curl

RUN apk add jpeg-dev zlib-dev freetype-dev lcms2-dev openjpeg-dev tiff-dev tk-dev tcl-dev

RUN apk add graphviz lzo-dev squashfs-tools

RUN pip install --upgrade pip
RUN pip install reportlab wheel graphviz ubi_reader python-lzo

RUN wget -O /tmp/binwalk.zip ${BINWALK_URL}
WORKDIR /
RUN unzip /tmp/binwalk.zip
WORKDIR /binwalk-master
RUN python3 setup.py install

RUN apk add --no-cache -t .build-deps wget ca-certificates unzip \
    && wget --progress=bar:force -O /tmp/ghidra.zip ${GHIDRA_URL} \
    && echo "${GHIDRA_SHA}  /tmp/ghidra.zip" | sha256sum -c - \
    && unzip /tmp/ghidra.zip \
    && mv ghidra_${VERSION} /ghidra \
    && chmod +x /ghidra/ghidraRun \
    && echo "===> Clean up unnecessary files..." \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives /tmp/* /var/tmp/* \
    && rm -rf /ghidra/docs \
    && rm -rf /ghidra/licenses \
    && rm -rf /ghidra/Extensions/Ghidra \
    && rm -rf /ghidra/Extensions/Eclipse \
    && find /ghidra -type f -name "*src*.zip" -exec rm -f {} \; \
    && apk del --purge .build-deps

WORKDIR /ghidra

RUN mkdir /home/FinjectRoute-main
COPY ./Scripts /home/FinjectRoute-main/Scripts

WORKDIR /home/FinjectRoute-main

RUN chmod 777 ./ -R

RUN mkdir -p ./Repository/FinjectRoute_tmp 
RUN mkdir -p ./Repository/Temp
RUN mkdir -p ./Logs/Taint_Analysis_Logs
RUN mkdir -p ./Output/PDFs
RUN mkdir -p ./Output/Graphs
RUN mkdir -p ./Input
RUN mkdir -p ./Scripts/tempJSON


COPY Scripts/Utility/json-20220320.jar /ghidra/Ghidra/patch/

WORKDIR /home/FinjectRoute-main/Scripts
