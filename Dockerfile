# Multi-stage build: compile a static binary, ship it on distroless.
# docker build -t netguard . && docker run --rm netguard version
FROM golang:1.24-alpine AS build
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
