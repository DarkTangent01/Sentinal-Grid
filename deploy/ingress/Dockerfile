# Syslog ingress (rsyslog). Deliberately tiny and pinned: deploys of the SIEM code never rebuild it.
FROM alpine:3.24.3@sha256:be2656061b536c1883c4034790e21d0a09c5aaaf51968b89368a3c0371ea2c9a
RUN apk upgrade --no-cache && apk add --no-cache rsyslog=8.2608.0-r0 conntrack-tools=1.4.9-r0 \
    && adduser -S -D -H -u 10002 ingress \
    && mkdir -p /var/spool/rsyslog && chown ingress /var/spool/rsyslog
COPY rsyslog.conf /etc/rsyslog.conf
USER 10002
EXPOSE 5514/udp 5514/tcp
# pidfile in /tmp, not on the spool volume: a stale one left by a killed rsyslogd would make every restart fail
COPY fix-conntrack.sh /usr/local/bin/fix-conntrack.sh
CMD ["rsyslogd", "-n", "-f", "/etc/rsyslog.conf", "-i", "/tmp/rsyslogd.pid"]
