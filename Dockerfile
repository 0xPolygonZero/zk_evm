# syntax=docker/dockerfile:1
# This is loosely based on `docker init`'s rust template.
# For a completely clean build, run something like this:
# ```
# docker build --build-arg=PROFILE=dev --no-cache
# ```

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

# statically-link the C runtime for runtime performance
RUSTFLAGS="-C target-feature=+crt-static" \
    # use the cache mount
    # (we will not be able to to write to e.g `/src/target` because it is bind-mounted)
    CARGO_TARGET_DIR=/artifacts \
    cargo build --locked "--profile=${PROFILE}" --target=x86_64-unknown-linux-gnu --all

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
find "/artifacts/x86_64-unknown-linux-gnu" \
    -maxdepth 2 \
    -type f \
    -executable \
    -not -name '*.so' \
    -exec cp '{}' /output \; \
    -print

EOF

##################
# Final executable
##################
FROM debian:bullseye-slim AS final

# Install runtime dependencies.
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libjemalloc2 \
    && rm -rf /var/lib/apt/lists/*

# this keeps this build target agnostic to the build profile
COPY --from=build ["/output/rpc", "/output/leader", "/output/worker", "/output/verifier", "/usr/local/bin/"]

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

