# syntax=docker/dockerfile:1
ARG BASE_IMAGE=docker/sandbox-templates:claude-code@sha256:868e3f5ef10579e06903d42e86448851ed59319ab8b9fba6dea2772c449bb2a6
FROM node:24.16.0-bookworm-slim@sha256:2c87ef9bd3c6a3bd4b472b4bec2ce9d16354b0c574f736c476489d09f560a203 AS node
FROM amazon/aws-cli:2.35.9@sha256:01be46681e0bd75da54c2ca7c4edad9ecd29499f664cac5f6cbf0a189d67d0f3 AS aws
FROM jdxcode/mise:2026.9.13@sha256:1e74fb7d744027d453731d948dda0748cf19a3e7b4357b09787448088d1ff2ad AS mise
FROM ${BASE_IMAGE}
USER root
COPY --from=node /usr/local/bin/node /usr/local/bin/node
COPY --from=mise /usr/local/bin/mise /usr/local/bin/mise
COPY --from=aws /usr/local/aws-cli /usr/local/aws-cli
RUN ln -sf /usr/local/aws-cli/v2/current/bin/aws /usr/local/bin/aws
COPY sandbox/bootstrap.ts /opt/readonly-sandbox/bootstrap.ts
RUN node --version && aws --version && git --version && jq --version && mise --version
USER agent
WORKDIR /home/agent/workspace
