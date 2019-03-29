FROM alpine:3.9

ENV FRONTMAN_VERSION=1.0.1-rc9

ENV FRONTMAN_HUB_URL=https://hub.cloudradar.io/checks/
# User and password should be passed via -e when starting the container
#ENV FRONTMAN_HUB_USER=XXXXXXXXX
#ENV FRONTMAN_HUB_PASSWORD=XXXXXXXX

RUN apk update && apk add ca-certificates

RUN wget https://github.com/cloudradar-monitoring/frontman/releases/download/${FRONTMAN_VERSION}/frontman_${FRONTMAN_VERSION}_Linux_x86_64.tar.gz && \
    tar xf frontman_${FRONTMAN_VERSION}_Linux_x86_64.tar.gz && \
    mv frontman /usr/local/bin && \
    mkdir /etc/frontman && \
    mv example.config.toml /etc/frontman/config.toml && \
    rm -rf frontman_${FRONTMAN_VERSION}_Linux_x86_64 && \
    rm frontman_${FRONTMAN_VERSION}_Linux_x86_64.tar.gz

CMD /usr/local/bin/frontman
