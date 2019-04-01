FROM alpine:3.9

ENV FRONTMAN_HUB_URL=https://hub.cloudradar.io/checks/
# User and password should be passed via -e when starting the container
#ENV FRONTMAN_HUB_USER=XXXXXXXXX
#ENV FRONTMAN_HUB_PASSWORD=XXXXXXXX

RUN apk update && apk add ca-certificates

COPY dist/linux_amd64/frontman /usr/local/bin/frontman

CMD [/usr/local/bin/frontman]
