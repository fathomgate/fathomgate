# Multi-stage build: compile a static binary, ship it on distroless.
# docker build -t netguard . && docker run --rm netguard version
# The golang image sets GOTOOLCHAIN=local, so it builds with its own Go: keep
# its minor equal to the go.mod `toolchain` line (ADR 0013). Release binaries
# come from GoReleaser, not from this file.
# Both base images are pinned as tag@sha256 to the multi-arch index digest
# (not a single-platform manifest); Dependabot's docker ecosystem keeps the
# digests current. Re-resolve by hand with
#   docker buildx imagetools inspect <image>:<tag>   (the top-level Digest)
FROM golang:1.26-alpine@sha256:8ac98ca534ac3f51e1f420a1dd2c15e74c75cfa0f23f3ad27eb5d7236c349a0c AS build
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

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
WORKDIR /etc/netguard
COPY --from=build /out/netguard /usr/local/bin/netguard
COPY policies/examples /etc/netguard/policies/examples
COPY profiles /etc/netguard/profiles
COPY inventory.example.yaml /etc/netguard/inventory.example.yaml
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/netguard"]
CMD ["serve"]
