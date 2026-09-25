# Multi-stage build: compile a static binary, ship it on distroless.
# docker build -t fathomgate . && docker run --rm fathomgate version
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
      -o /out/fathomgate ./cmd/fathomgate

FROM gcr.io/distroless/static-debian12:nonroot@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab
WORKDIR /etc/fathomgate
COPY --from=build /out/fathomgate /usr/local/bin/fathomgate
# Licence, attributions and every linked module's licence text (ADR 0020).
COPY LICENSE NOTICE /usr/share/doc/fathomgate/
COPY THIRD_PARTY_LICENSES /usr/share/doc/fathomgate/THIRD_PARTY_LICENSES
COPY policies/examples /etc/fathomgate/policies/examples
# The binary embeds these profiles (ADR 0027); the copy is for --profiles.
COPY profiles/*.yaml profiles/LICENSE /etc/fathomgate/profiles/
COPY inventory.example.yaml /etc/fathomgate/inventory.example.yaml
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/fathomgate"]
CMD ["serve"]
