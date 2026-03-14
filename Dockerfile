FROM ubuntu:22.04

ENV DEBIAN_FRONTEND=noninteractive
ENV RUNNER_VERSION=2.327.1

RUN apt-get update && apt-get install -y \
    curl \
    ca-certificates \
    git \
    jq \
    sudo \
    unzip \
    libicu70 \
    && rm -rf /var/lib/apt/lists/*

RUN useradd -m runner && \
    mkdir -p /home/runner/actions-runner && \
    chown -R runner:runner /home/runner

WORKDIR /home/runner/actions-runner

RUN curl -fsSL -o actions-runner.tar.gz \
    "https://github.com/actions/runner/releases/download/v${RUNNER_VERSION}/actions-runner-linux-x64-${RUNNER_VERSION}.tar.gz" && \
    tar xzf actions-runner.tar.gz && \
    rm actions-runner.tar.gz

COPY start.sh /start.sh
RUN chmod +x /start.sh && chown runner:runner /start.sh

USER runner

ENTRYPOINT ["/start.sh"]