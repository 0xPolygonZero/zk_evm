# syntax=docker/dockerfile:1
# This is loosely based on `docker init`'s rust template.
# For a completely clean build, run something like this:
# ```
# docker build --build-arg=PROFILE=dev --no-cache
# ```
#
# There is a build target[^1] for each artifact we want.
#
# [^1]: https://docs.docker.com/build/building/multi-stage/

#############
# Build stage
#############
# - `/src` is the repo directory.
# - `/artifacts` is $CARGO_TARGET_DIR.
# - `/output` is where the binaries go.

ARG BUILD_BASE=rustlang/rust:nightly-bullseye-slim
FROM ${BUILD_BASE} AS build

# Install build dependencies.
RUN apt-get update && apt-get install -y \
    # for jemalloc
    libjemalloc-dev \
    libjemalloc2 \
    make \
    # for openssl
    libssl-dev \
    pkg-config \
    # clean the image
    && rm -rf /var/lib/apt/lists/*

ARG PROFILE=release
# forward the docker argument so that the script below can read it
ENV PROFILE=${PROFILE}

# Build the application.
RUN \
    # mount the repository so we don't have to COPY it in
    --mount=type=bind,source=.,target=/src \
    # cache artifacts and the cargo registry to speed up subsequent builds
    --mount=type=cache,target=/artifacts \
    --mount=type=cache,target=/usr/local/cargo/registry/ \
    # run the build
    <<EOF
set -eux

# need to change workdir instead of using --manifest-path because we need
# .cargo/config.toml
cd /src

# use the cache mount
# (we will not be able to to write to e.g `/src/target` because it is bind-mounted)
CARGO_TARGET_DIR=/artifacts cargo build --locked "--profile=${PROFILE}" --all

# narrow the find call to SUBDIR because if we just copy out all executables
# we will break the cache invariant
if [ "$PROFILE" = "dev" ]; then
    SUBDIR=debug # edge case
else
    SUBDIR=$PROFILE
fi

# maxdepth because binaries are in the root
# - other folders contain build scripts etc.
mkdir /output
find "/artifacts/$SUBDIR" \
    -maxdepth 1 \
    -type f \
    -executable \
    -not -name '*.so' \
    -exec cp '{}' /output \; \
    -print

EOF

##########################
# Base for the final image
##########################
FROM debian:bullseye-slim AS base

# Install runtime dependencies.
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libjemalloc2 \
    libssl-dev \
    tini \
    && rm -rf /var/lib/apt/lists/*

# Create a non-privileged user that the app will run under.
# See https://docs.docker.com/develop/develop-images/dockerfile_best-practices/#user
ARG UID=10001
RUN adduser \
    --disabled-password \
    --gecos "" \
    --home "/nonexistent" \
    --shell "/sbin/nologin" \
    --no-create-home \
    --uid "${UID}" \
    user
USER user

####################################
# Final executables with entrypoints
####################################
FROM base AS leader

# TODO(0xaatif): https://github.com/0xPolygonZero/zk_evm/issues/356
#                this is bad practice
COPY .env /

COPY --from=build /output/leader /usr/local/bin/
COPY --from=build /output/rpc /usr/local/bin/
RUN leader --help && rpc --help
ENTRYPOINT [ "tini", "--", "leader" ]

FROM base AS worker

COPY --from=build /output/worker /usr/local/bin/
RUN worker --help
ENTRYPOINT [ "tini", "--", "worker" ]
