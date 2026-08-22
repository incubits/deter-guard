# deter-guard — the image a CI job runs.
#
#   docker build -t deter-guard .
#
# The CLI is bundled to a single file with esbuild, so the runtime image carries no node_modules and
# nothing but the interpreter and one script. That keeps it small — it's pulled on every pipeline run
# — and it keeps the attack surface of a container that handles credentials small too. A guard that
# shipped a dependency tree would be an odd thing to put in front of a supply-chain problem.

# ---- build ----------------------------------------------------------------------------------
FROM node:22-alpine AS build
ENV PNPM_HOME=/pnpm
ENV PATH=$PNPM_HOME:$PATH
RUN corepack enable
WORKDIR /app

# Manifests first, so the install layer is cached until a dependency actually changes.
# pnpm-workspace.yaml carries allowBuilds, so it has to be present for the install to run
# esbuild postinstall.
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./
RUN pnpm install --frozen-lockfile

COPY tsconfig.base.json tsconfig.json build.mjs ./
COPY src ./src
RUN pnpm build

# ---- runtime --------------------------------------------------------------------------------
FROM node:22-alpine AS runtime
ENV NODE_ENV=production

# Non-root. The guard reads env vars, talks HTTPS, and writes the policy where it's told; it has no
# reason to run privileged, and a CI runner is exactly where that matters.
RUN addgroup -S deter && adduser -S -G deter deter

COPY --from=build /app/dist/cli.js /usr/local/bin/deter-guard
RUN chmod 0755 /usr/local/bin/deter-guard

USER deter
WORKDIR /workspace

# No default args: `docker run deter-guard policy` reads naturally, and a bare run prints usage
# rather than doing something.
ENTRYPOINT ["/usr/local/bin/deter-guard"]
