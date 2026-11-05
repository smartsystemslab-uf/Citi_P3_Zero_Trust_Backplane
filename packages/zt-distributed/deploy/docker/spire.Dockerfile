# Build context: distributed_runtime/ (docker build -f deploy/docker/spire.Dockerfile -t citi-ztbp/spire:1.15.3 .)
# SPIRE 1.15.3 built from the official release tarball
# (sha256 ca1a4d1155317bdd2afc7f36663828a10410c7c840e54725b90b4064b0a301c7,
# verified against spire-1.15.3-linux-amd64-musl_sha256sum.txt). The ghcr.io
# images could not be pulled by the Docker daemon on this host (registry token
# request returned 403), so the static release binaries are used instead.
FROM python:3.11-slim@sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e
COPY deploy/vendor/spire-1.15.3-linux-amd64-musl.tar.gz /tmp/spire.tgz
RUN echo "ca1a4d1155317bdd2afc7f36663828a10410c7c840e54725b90b4064b0a301c7  /tmp/spire.tgz" | sha256sum -c - \
 && mkdir -p /opt/spire && tar xzf /tmp/spire.tgz -C /opt/spire --strip-components=1 && rm /tmp/spire.tgz \
 && ln -s /opt/spire/bin/spire-server /usr/local/bin/spire-server \
 && ln -s /opt/spire/bin/spire-agent /usr/local/bin/spire-agent
WORKDIR /opt/spire
