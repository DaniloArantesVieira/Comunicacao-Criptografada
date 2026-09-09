FROM alpine:3.20

RUN apk add --no-cache openvpn bash iproute2

WORKDIR /server

COPY server.conf /server/server.conf
COPY ccd /server/ccd
COPY scripts /server/scripts

RUN chmod +x /server/scripts/entrypoint.sh

CMD ["/server/scripts/entrypoint.sh"]
