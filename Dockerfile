# deter-guard — the image a CI job runs.
#
#   docker build -t deter-guard .
#
# The runtime stage is FROM scratch. It contains three things: the static binary, a CA bundle so TLS
# works, and a passwd entry so it can run as a non-root user. No shell, no package manager, no
# language runtime, nothing to patch. A tool whose job is to stand in front of a supply-chain problem
# shouldn't bring one along — and the smaller it is, the faster every pipeline run pulls it.
#
# The binary is CGO_ENABLED=0 static, so it needs no libc at all.

# ---- build ----------------------------------------------------------------------------------
# --platform=$BUILDPLATFORM keeps the compiler running NATIVELY on the builder while producing a
# binary for the target. Go cross-compiles by itself, so an arm64 image needs no QEMU emulation —
# both much faster and one less moving part than emulating a whole toolchain.
FROM --platform=$BUILDPLATFORM docker.io/library/golang:1.25-alpine AS build
WORKDIR /src

# No dependencies to fetch: go.mod has no `require` block. Copying it first still caches the module
# step, and means adding a dependency invalidates that layer as it should.
COPY go.mod ./
RUN go mod download

# roots.pem is //go:embed-ed into the binary (roots.go), so the build fails without it rather than
# producing a guard that cannot verify its own TLS.
COPY *.go roots.pem ./

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=dev
# -trimpath strips local filesystem paths, so the binary is reproducible and doesn't leak the build
# machine's layout. -s -w drops the symbol table and DWARF, which is most of the size saving.
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o /out/deter-guard .

# ---- certificates and a user ----------------------------------------------------------------
# Both come from a real distro image rather than being hand-written, so the CA bundle is a maintained
# one. Nothing from this stage ships except these two files.
FROM docker.io/library/alpine:3.21 AS certs
RUN apk add --no-cache ca-certificates
# scratch has no /etc/passwd, so the numeric UID below would have no name. Harmless in itself, but
# anything that looks it up complains, and one line is cheaper than explaining that later.
RUN echo 'deter:x:65532:65532:deter:/:/sbin/nologin' > /passwd.min

# ---- runtime --------------------------------------------------------------------------------
FROM scratch
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=certs /passwd.min /etc/passwd
COPY --from=build /out/deter-guard /deter-guard

# Never root. A CI runner is exactly where that matters, and nothing in here needs it.
USER 65532:65532
WORKDIR /workspace

# No default args: `docker run deter-guard policy` reads naturally, and a bare run prints usage
# rather than doing something.
ENTRYPOINT ["/deter-guard"]
