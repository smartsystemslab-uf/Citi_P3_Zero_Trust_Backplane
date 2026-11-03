# Runtime image of the distributed runtime (gateway PEP, agent workloads, agent-credential
# issuer, ingress client, ops helper). Build context: the Backplane root (filtered by
# runtime.Dockerfile.dockerignore); named context `citi_mas`: a staged read-only copy of
# D:\Lab\Citi_P3 without secrets/venvs/runtime data (scripts/stage_mas.py).
#   docker build -f distributed_runtime/deploy/docker/runtime.Dockerfile \
#       --build-context citi_mas=distributed_runtime/runtime/build/Citi_P3 -t citi-ztbp/runtime:dev .
FROM python:3.11-slim@sha256:e41613d42d4891e4930f79523f93f81bbc7632584ec65e36ab055f41a800b41e

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

COPY distributed_runtime/deploy/locks/runtime.lock.txt /tmp/requirements.txt
RUN pip install -r /tmp/requirements.txt && pip freeze > /opt/pip-freeze.txt

COPY --from=citi_mas . /opt/citi/Citi_P3
COPY . /opt/citi/Citi_P3_Zero_Trust_Backplane

ENV BP=/opt/citi/Citi_P3_Zero_Trust_Backplane
ENV PYTHONPATH=${BP}/distributed_runtime:${BP}/zero_trust_identity/src:${BP}/zero_trust_psl/src:${BP}/zero_trust_pdp_task4_secure/src:/opt/citi/Citi_P3/citi_banking_adk \
    CITI_MAS_ROOT=/opt/citi/Citi_P3 \
    CITI_BACKPLANE_ROOT=${BP}

# Fail the build if: the time-zone database is missing (PSL time windows), committed
# development keys or MAS secrets made it into the image, or the policy store does not compile.
RUN python -c "from zoneinfo import ZoneInfo; ZoneInfo('America/New_York')" \
 && test ! -e ${BP}/zero_trust_pdp_task4_secure/security/dev_keys \
 && test ! -e /opt/citi/Citi_P3/citi_banking_adk/.env \
 && test ! -e /opt/citi/Citi_P3/citi_banking_adk/.venv \
 && python -m zt_psl.cli check --catalog ${BP}/zero_trust_pdp_task4_secure/policy_store/policy_fields.yaml \
        ${BP}/zero_trust_pdp_task4_secure/policy_store/*.psl > /dev/null \
 && chmod -R a+rX /opt/citi
WORKDIR /opt/citi/Citi_P3_Zero_Trust_Backplane/distributed_runtime
