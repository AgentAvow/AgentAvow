# AgentAvow scan as a Bitbucket Pipe: ghcr.io/agentavow/scanner:pipe-0.1
#
# The scanner image plus an entrypoint, because a pipe runs its image's entrypoint
# with the pipe's `variables:` as environment. Built and pushed by CI from main after
# the scanner image (.github/workflows/ci.yml, scanner-image job).
#
#   docker build -f bitbucket/Dockerfile --build-arg SCANNER_IMAGE=ghcr.io/agentavow/scanner:0.1 bitbucket
ARG SCANNER_IMAGE=ghcr.io/agentavow/scanner:0.1
FROM ${SCANNER_IMAGE}
COPY pipe.yml /pipe.yml
ENTRYPOINT ["agentavow-bitbucket"]
