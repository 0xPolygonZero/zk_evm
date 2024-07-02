# syntax=docker/dockerfile:1
# This is loosely based on `docker init`'s rust template.
# For a completely clean build, run something like this:
# ```
# docker build --build-arg=PROFILE=dev --build-arg=ENTRYPOINT=leader --no-cache
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

##################
# Final executable
##################
FROM debian:bullseye-slim AS final

# Install runtime dependencies.
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libjemalloc2 \
    libssl-dev \
    tini \
    && rm -rf /var/lib/apt/lists/*

COPY --from=build /output/* /usr/local/bin/
RUN <<EOF
set -eux
: smoke test executables
find /usr/local/bin -type f -executable -print0 \
    | xargs --null --replace tini -- {} --help
EOF

# can't refer to docker args in an ENTRYPOINT directive, so go through a symlink
ARG ENTRYPOINT
RUN ln --symbolic --verbose -- "$(which ${ENTRYPOINT})" /entrypoint
ENTRYPOINT [ "tini", "--", "/entrypoint" ]

# TODO(0xaatif): https://github.com/0xPolygonZero/zk_evm/issues/356
#                this is bad practice
COPY .env /

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

