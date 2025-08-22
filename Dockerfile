FROM golang:1.24-alpine3.21 AS builder

ARG VERSION=dev

COPY cert-manager /go/src/app
WORKDIR /go/src/app

RUN GOOS=linux go build -o bin -ldflags="-X 'main.version=$VERSION'" main.go

FROM nginx:1.27.5-alpine

RUN mkdir -p /opt/certs
RUN mkdir -p /opt/dummy-certs
RUN mkdir -p /opt/cert-manager
COPY --from=builder /go/src/app/bin /opt/cert-manager/bin
COPY --from=builder /go/src/app/docs /opt/cert-manager/docs
COPY include/certs /opt/certs
COPY include/certs /opt/dummy-certs
COPY include/config/nginx.conf /etc/nginx/nginx.conf
COPY include/config/templates /etc/nginx/templates
COPY include/pairing /opt/pairing
COPY include/docker-entrypoint.sh /docker-entrypoint.sh

ENTRYPOINT ["/docker-entrypoint.sh"]

EXPOSE 80
EXPOSE 1883
EXPOSE 8080

STOPSIGNAL SIGQUIT

CMD ["nginx", "-g", "'daemon off;'"]
