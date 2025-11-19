FROM nicolaka/netshoot
USER root

RUN apk update && apk add --no-cache dhcpcd sntpc make

WORKDIR /app/traffic_tunnel_source
COPY ./traffic_tunnel_source/ .

RUN make

RUN mv traffic_tunnel /usr/local/bin/traffic_tunnel
WORKDIR /app