FROM golang:1.25.9-alpine3.22@sha256:ea77c38bc50df598f22ae02b729b9d37eb0d70ed72d6dd336b8d6c02ae2b8b09 AS builder
ARG VERSION=dev-snapshot
RUN mkdir /build
RUN apk add --update make
WORKDIR /build
ADD . /build
RUN make BUILD_VERSION=${VERSION}

FROM alpine:3.23.4@sha256:5b10f432ef3da1b8d4c7eb6c487f2f5a8f096bc91145e68878dd4a5019afde11 AS runner
LABEL org.opencontainers.image.source="https://github.com/DataDog/stratus-red-team/"
COPY --from=builder /build/bin/stratus /stratus
RUN apk add --update git # git is needed for Terraform to download external modules at runtime
ENTRYPOINT ["/stratus"]
CMD ["--help"]
