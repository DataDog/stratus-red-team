FROM golang:1.23.2-alpine3.20@sha256:9dd2625a1ff2859b8d8b01d8f7822c0f528942fe56cfe7a1e7c38d3b8d72d679 AS builder
ARG VERSION=dev-snapshot
RUN mkdir /build
RUN apk add --update make
WORKDIR /build
ADD . /build
RUN make BUILD_VERSION=${VERSION}

FROM alpine:3.21.0@sha256:21dc6063fd678b478f57c0e13f47560d0ea4eeba26dfc947b2a4f81f686b9f45 AS runner
LABEL org.opencontainers.image.source="https://github.com/DataDog/stratus-red-team/"
COPY --from=builder /build/bin/stratus /stratus
RUN apk add --update git # git is needed for Terraform to download external modules at runtime
ENTRYPOINT ["/stratus"]
CMD ["--help"]
