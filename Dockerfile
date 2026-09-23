# Multi-stage build: compile a static binary, ship it on distroless.
# docker build -t netguard . && docker run --rm netguard version
# The golang image sets GOTOOLCHAIN=local, so it builds with its own Go: keep
# its minor equal to the go.mod `toolchain` line (ADR 0013). Release binaries
# come from GoReleaser, not from this file.
FROM golang:1.26-alpine AS build
WORKDIR /src
ENV CGO_ENABLED=0 GOFLAGS=-trimpath
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown
RUN go build -ldflags "-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
      -o /out/netguard ./cmd/netguard

FROM gcr.io/distroless/static-debian12:nonroot
WORKDIR /etc/netguard
COPY --from=build /out/netguard /usr/local/bin/netguard
COPY policies/examples /etc/netguard/policies/examples
COPY profiles /etc/netguard/profiles
COPY inventory.example.yaml /etc/netguard/inventory.example.yaml
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/netguard"]
CMD ["serve"]
