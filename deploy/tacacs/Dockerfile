# TACACS+ server for Sentinel Grid: tac_plus-ng (event-driven-servers, Marc Huber), built from a pinned commit, plus the
# SIEM's deploy agent. Opt-in: started only with COMPOSE_PROFILES=tacacs (see docs/TACACS.md).
#
# Upstream describes tac_plus-ng as work in progress: test in a lab before pointing production devices at it, and keep
# device-local emergency access configured.
FROM debian:12.7-slim AS build
ARG TAC_PLUS_NG_COMMIT=dc3ce306f0a9753c2ae8cb4cc761d8c8a33b7b6b
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates git make clang perl libpcre2-dev libssl-dev libc-ares-dev \
    && rm -rf /var/lib/apt/lists/*
RUN git clone https://github.com/MarcJHuber/event-driven-servers /src && cd /src && git checkout "$TAC_PLUS_NG_COMMIT" \
    && ./configure --prefix=/usr/local tac_plus-ng mavis && make && make install \
    && test -x /usr/local/sbin/tac_plus-ng && ls /usr/local/sbin /usr/local/lib/mavis
# upstream's install ignores DESTDIR, so it installs into this stage's (otherwise empty) /usr/local, copied below

FROM debian:12.7-slim
ARG TAC_PLUS_NG_COMMIT=dc3ce306f0a9753c2ae8cb4cc761d8c8a33b7b6b
ENV TAC_PLUS_NG_COMMIT=$TAC_PLUS_NG_COMMIT
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates python3 perl libpcre2-8-0 libssl3 libc-ares2 \
        libnet-ldap-perl libio-socket-ssl-perl libcap2-bin util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10050 tacshare \
    && useradd --system --uid 10003 --gid tacshare --home /nonexistent --shell /usr/sbin/nologin tacacs
COPY --from=build /usr/local /usr/local
# bind TCP/49 without running as root
RUN setcap cap_net_bind_service=+ep /usr/local/sbin/tac_plus-ng && ldconfig
COPY agent.py /opt/tacagent/agent.py
COPY entrypoint.sh /opt/tacagent/entrypoint.sh
COPY bootstrap.cfg /opt/tacagent/bootstrap.cfg
RUN chmod 0555 /opt/tacagent/entrypoint.sh /opt/tacagent/agent.py
EXPOSE 49/tcp
ENTRYPOINT ["/opt/tacagent/entrypoint.sh"]
