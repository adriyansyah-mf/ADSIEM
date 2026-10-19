Name:           siem-agent
Version:        %{_version}
Release:        1%{?dist}
Summary:        SIEM Platform log collection agent
License:        MIT
URL:            https://github.com/siem-platform/agent
BuildArch:      %{_build_arch}

Requires:       systemd
Requires(pre):  shadow-utils
Requires(post): systemd
Requires(preun): systemd
Requires(postun): systemd

%description
Lightweight agent that tails log files, encodes entries with
exponential-backoff delivery, and ships them to the SIEM server API.
Supports automatic enrollment and dynamic log source management.

%install
install -Dm755 %{_sourcedir}/siem-agent          %{buildroot}/usr/bin/siem-agent
install -Dm755 %{_sourcedir}/siem-agent-configure %{buildroot}/usr/sbin/siem-agent-configure
install -Dm644 %{_sourcedir}/siem-agent.service   %{buildroot}/lib/systemd/system/siem-agent.service
install -Dm640 %{_sourcedir}/config.yaml          %{buildroot}/etc/siem-agent/config.yaml
install -d     %{buildroot}/var/lib/siem-agent

%pre
getent group  siem-agent >/dev/null || groupadd --system siem-agent
getent passwd siem-agent >/dev/null || \
  useradd --system --no-create-home --shell /sbin/nologin \
          --gid siem-agent --home /var/lib/siem-agent siem-agent
exit 0

%post
chown -R siem-agent:siem-agent /var/lib/siem-agent
chmod 750 /var/lib/siem-agent
chown siem-agent:siem-agent /etc/siem-agent/config.yaml
# explicit rather than %systemd_* macros: rpmbuild on the Debian-based builder doesn't define them
systemctl daemon-reload >/dev/null 2>&1 || :
[ "$1" -eq 1 ] && systemctl enable siem-agent.service >/dev/null 2>&1 || :
if [ -n "${SIEM_SERVER_URL:-}" ] || [ -n "${SIEM_ENROLLMENT_KEY:-}" ]; then
  # one-line install from the dashboard: configure, enroll and start now
  /usr/sbin/siem-agent-configure --if-env
elif [ "$1" -eq 1 ]; then
  echo "siem-agent installed. Point it at your server and enroll it with:"
  echo "  sudo siem-agent-configure --server https://<siem-server> --key <enrollment key>"
fi

%preun
if [ "$1" -eq 0 ]; then
  systemctl disable --now siem-agent.service >/dev/null 2>&1 || :
fi

%postun
systemctl daemon-reload >/dev/null 2>&1 || :
if [ "$1" -ge 1 ]; then
  systemctl try-restart siem-agent.service >/dev/null 2>&1 || :
fi
if [ "$1" -eq 0 ]; then
  userdel  siem-agent 2>/dev/null || true
  groupdel siem-agent 2>/dev/null || true
  rm -rf /etc/siem-agent /var/lib/siem-agent
fi

%files
%attr(755,root,root) /usr/bin/siem-agent
%attr(755,root,root) /usr/sbin/siem-agent-configure
%attr(644,root,root) /lib/systemd/system/siem-agent.service
%config(noreplace) %attr(600,siem-agent,siem-agent) /etc/siem-agent/config.yaml
%attr(750,siem-agent,siem-agent) /var/lib/siem-agent

%changelog
* Thu May 21 2026 SIEM Platform <admin@example.com> - 1.0.0-1
- Initial release
