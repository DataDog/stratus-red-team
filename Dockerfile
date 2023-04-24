FROM golang:1.20.2-alpine3.16@sha256:1d7fec2b8f451917a45b3e41249d1b5474c5269cf03f5cbdbd788347a1f1237c AS builder
ARG VERSION=dev-snapshot
RUN mkdir /build
RUN apk add --update make
WORKDIR /build
ADD . /build
RUN make BUILD_VERSION=${VERSION}

FROM alpine:3.17.3@sha256:124c7d2707904eea7431fffe91522a01e5a861a624ee31d03372cc1d138a3126 AS runner
LABEL org.opencontainers.image.source="https://github.com/DataDog/stratus-red-team/"
COPY --from=builder /build/bin/stratus /stratus
RUN apk add --update git # git is needed for Terraform to download external modules at runtime
ENTRYPOINT ["/stratus"]
CMD ["--help"]
