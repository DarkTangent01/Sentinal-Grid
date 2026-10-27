# Syslog ingress (rsyslog). Deliberately tiny and pinned: deploys of the SIEM code never rebuild it.
FROM alpine:3.20.3
RUN apk add --no-cache rsyslog=8.2404.0-r0 conntrack-tools \
    && adduser -S -D -H -u 10002 ingress \
    && mkdir -p /var/spool/rsyslog && chown ingress /var/spool/rsyslog
COPY rsyslog.conf /etc/rsyslog.conf
USER ingress
EXPOSE 5514/udp 5514/tcp
# pidfile in /tmp, not on the spool volume: a stale one left by a killed rsyslogd would make every restart fail
COPY fix-conntrack.sh /usr/local/bin/fix-conntrack.sh
CMD ["rsyslogd", "-n", "-f", "/etc/rsyslog.conf", "-i", "/tmp/rsyslogd.pid"]
