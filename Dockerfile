FROM nicolaka/netshoot
USER root
RUN apk update && apk add --no-cache dhcpcd sntpc