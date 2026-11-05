# Vendored SPIRE release (not committed)

`spire.Dockerfile` builds the SPIRE server/agent image from the official static release
`spire-1.15.3-linux-amd64-musl.tar.gz` (sha256 in `spire-1.15.3-linux-amd64-musl_sha256sum.txt`,
checked during the build). The tarball is 64 MB and is git-ignored. Place it here before
`zt-distributed build`:

    https://github.com/spiffe/spire/releases/download/v1.15.3/spire-1.15.3-linux-amd64-musl.tar.gz

(The ghcr.io SPIRE images could not be pulled by the Docker daemon on the development host,
so the release binaries are used.)
