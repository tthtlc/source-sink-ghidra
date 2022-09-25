FROM openjdk:17-slim

ENV VERSION 10.1.4_PUBLIC
ENV GHIDRA_SHA 91556c77c7b00f376ca101a6026c0d079efbf24a35b09daaf80bda897318c1f1
ENV GHIDRA_URL https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.1.4_build/ghidra_10.1.4_PUBLIC_20220519.zip

ENV GHIDRA_DIRECTORY /ghidra/support/analyzeHeadless

USER root

RUN apt-get update && apt-get install -y unzip wget python2 graphviz\
    && wget --progress=bar:force -O /tmp/ghidra.zip ${GHIDRA_URL} \
    && unzip /tmp/ghidra.zip \
    && mv ghidra_${VERSION} /ghidra \
    && chmod +x /ghidra/ghidraRun \
    && echo "===> Clean up unnecessary files..." \
    && rm -rf /var/lib/apt/lists/* /var/cache/apt/archives /tmp/* /var/tmp/* \
    && rm -rf /ghidra/docs \
    && rm -rf /ghidra/licenses \
    && rm -rf /ghidra/Extensions/Ghidra \
    && rm -rf /ghidra/Extensions/Eclipse \
    && rm -rf /tmp/ghidra.zip

WORKDIR /ghidra/scripts

ADD . /ghidra/scripts

ARG USER_ID
ARG GROUP_ID

RUN addgroup --gid $GROUP_ID user
RUN adduser --disabled-password --gecos '' --uid $USER_ID --gid $GROUP_ID user
USER user

ENV INPUT_FOLDER /samples/
ENTRYPOINT [ "python2" ]
CMD ["/ghidra/scripts/ghost_launcher_headless.py"]