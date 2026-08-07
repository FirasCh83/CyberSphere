FROM alpine:3.20

ARG NUCLEI_VERSION=3.4.10

RUN apk add --no-cache \
    ca-certificates \
    wget \
    unzip

RUN wget -q \
    "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
    -O /tmp/nuclei.zip \
    && unzip /tmp/nuclei.zip -d /usr/local/bin \
    && rm -f /tmp/nuclei.zip \
    && chmod +x /usr/local/bin/nuclei

RUN nuclei -version

RUN nuclei -update-templates

WORKDIR /app

ENTRYPOINT ["nuclei"]