ARG VERSION=dev-snapshot

FROM golang:1.17.6-alpine3.15 AS builder
RUN mkdir /build
RUN apk add --update make
WORKDIR /build
ADD . /build
RUN make BUILD_VERSION=${VERSION}

FROM alpine:3.15.0 AS runner
LABEL org.opencontainers.image.source="https://github.com/DataDog/stratus-red-team/"
COPY --from=builder /build/bin/stratus /stratus
ENTRYPOINT ["/stratus"]
CMD ["--help"]
