# deter-guard — the image a CI job runs.
#
#   docker build -t deter-guard .
#
# The runtime stage is FROM scratch. It contains four things: the static binary, a CA bundle so TLS
# works, a passwd entry so it can run as a non-root user, and one static busybox providing `sh` and
# `tail` — see the note on that stage for why a CI image has no choice about those two. No package
# manager, no language runtime, nothing that resolves a dependency at run time. A tool whose job is
# to stand in front of a supply-chain problem shouldn't bring one along — and the smaller it is, the
# faster every pipeline run pulls it.
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

# ---- a shell, because a CI job image is not run the way you run it -----------------------------
# Both platforms start a job image THEMSELVES rather than running its entrypoint. GitHub Actions
# creates the container with `--entrypoint tail <image> -f /dev/null` and then execs every step
# through `sh`; GitLab hands its `script:` to `sh` the same way. A pure-scratch image satisfies
# neither, and the failure lands before the first step as
#
#   OCI runtime create failed: exec: "tail": executable file not found in $PATH
#
# which reads like a broken runner rather than a missing shell, and cost us a customer-visible
# afternoon. Our own console tells people to use this image as their job image; the image has to be
# able to be one.
#
# This is the smallest way to do that: ONE static uclibc busybox (~1 MB) with two names hung off it.
# Nothing here can be upgraded in place, nothing resolves a dependency at run time, and there is
# still no package manager — which is the property "no shell" was standing in for. A shell that is a
# symlink to a single pinned static binary is not a supply chain.
FROM docker.io/library/busybox:1.37.0-uclibc AS shell
# Only the two names the runners actually invoke. Every other applet is reachable as
# `busybox <applet>`, so this is a smaller surface than a distro shell without being a smaller
# binary — the cost is the same either way, and the PATH stays honest about what is here.
#
# The third name is the guard itself. As an ENTRYPOINT the absolute path is enough, but a job
# container is started with the entrypoint REPLACED, and every step then says `deter-guard claim` —
# a bare name, resolved against PATH. Without this the image gets a shell and still fails, one step
# later, with `deter-guard: not found`.
RUN mkdir -p /min/bin \
 && ln -s /bin/busybox /min/bin/sh \
 && ln -s /bin/busybox /min/bin/tail \
 && ln -s /deter-guard  /min/bin/deter-guard

# ---- runtime --------------------------------------------------------------------------------
FROM scratch
COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=certs /passwd.min /etc/passwd
COPY --from=shell /bin/busybox /bin/busybox
COPY --from=shell /min/bin/ /bin/
COPY --from=build /out/deter-guard /deter-guard

# scratch carries no PATH, so every consumer would depend on the runtime's built-in default to find
# `sh` and `tail`. Spelling it out costs one line and removes that dependency; it is also what
# `exec` mode resolves the wrapped command against.
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# Never root. A CI runner is exactly where that matters, and nothing in here needs it.
USER 65532:65532
WORKDIR /workspace

# No default args: `docker run deter-guard policy` reads naturally, and a bare run prints usage
# rather than doing something.
ENTRYPOINT ["/deter-guard"]
