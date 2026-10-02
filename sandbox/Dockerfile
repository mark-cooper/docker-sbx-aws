# syntax=docker/dockerfile:1
# Shared tools layered onto every agent template; see Dockerfile.<agent>.
FROM node:24.21.0-bookworm-slim@sha256:0e0ff40c39bc087845bfb27465a0df4ea419520094bc35842ff83dd8cbe6f9b6 AS node
FROM amazon/aws-cli:2.37.8@sha256:420ab345e847291b541b45d989535f55bcff957c27fa1100fae4aa233e86398c AS aws
FROM jdxcode/mise:debian@sha256:8544c3c5648d98e93b22389ed8d208ec9470a2c92b027de85bb2dc4ed4545cb8 AS mise

FROM node AS assemble
COPY --from=aws /usr/local/aws-cli /out/usr/local/aws-cli
COPY --from=mise /usr/local/bin/mise /out/usr/local/bin/mise
COPY sandbox/bootstrap.ts /out/opt/readonly-sandbox/bootstrap.ts
RUN cp /usr/local/bin/node /out/usr/local/bin/node \
 && ln -s /usr/local/aws-cli/v2/current/bin/aws /out/usr/local/bin/aws

FROM scratch
COPY --from=assemble /out /
