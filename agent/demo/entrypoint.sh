#!/bin/bash
# Boots the agent-demo VM: company-profile app (MySQL → PHP-FPM → Apache on
# 1337) plus sshd, all writing to /var/log. The SIEM agent runs last and tails
# those very files, so every event it ships was produced by a real daemon.
set -e

mkdir -p /run/sshd /run/mysqld /var/log /var/log/apache2
chown mysql:mysql /run/mysqld || true

if [ ! -d /var/lib/mysql/mysql ]; then
  mysql_install_db --user=mysql --datadir=/var/lib/mysql >/dev/null 2>&1
fi
mysqld_safe --datadir=/var/lib/mysql >/dev/null 2>&1 &
for _ in $(seq 1 40); do
  mysqladmin ping >/dev/null 2>&1 && break
  sleep 1
done

mysql <<'SQL'
CREATE DATABASE IF NOT EXISTS company_profile;
CREATE USER IF NOT EXISTS 'cms'@'localhost' IDENTIFIED BY 'cms-lAB-pass';
GRANT ALL PRIVILEGES ON company_profile.* TO 'cms'@'localhost';
FLUSH PRIVILEGES;
USE company_profile;
CREATE TABLE IF NOT EXISTS staff (
  id INT AUTO_INCREMENT PRIMARY KEY,
  username VARCHAR(64) NOT NULL,
  password VARCHAR(128) NOT NULL,
  email VARCHAR(128)
);
INSERT IGNORE INTO staff (id, username, password, email)
VALUES (1, 'admin', 'admin123', 'admin@company.local'),
       (2, 'editor', 'editor123', 'editor@company.local');
CREATE TABLE IF NOT EXISTS posts (
  id INT AUTO_INCREMENT PRIMARY KEY,
  title VARCHAR(200),
  body TEXT
);
INSERT IGNORE INTO posts (id, title, body)
VALUES (1, 'Welcome', 'Company profile demo content.');
SQL

echo 'root:toor-lAB-demo' | chpasswd
id demo >/dev/null 2>&1 || useradd -m -s /bin/bash demo
echo 'demo:demo-lAB-pass' | chpasswd
sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config
sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config

rm -f /etc/rsyslog.d/*.conf
cat > /etc/rsyslog.d/50-lab.conf <<'EOF'
module(load="imuxsock")
auth,authpriv.*            /var/log/auth.log
*.*;auth,authpriv.none     -/var/log/syslog
EOF
touch /var/log/auth.log /var/log/syslog
chmod 640 /var/log/auth.log /var/log/syslog
rm -f /run/rsyslogd.pid
rsyslogd || echo "rsyslog failed to start (imklog is unavailable in containers)"

rm -f /var/log/apache2/access.log /var/log/apache2/error.log
touch /var/log/apache2/access.log /var/log/apache2/error.log
ln -sf /etc/apache2/conf-available/zz-lab.conf /etc/apache2/conf-enabled/zz-lab.conf

php-fpm -D
sleep 2
apache2ctl -D FOREGROUND &
sleep 2
/usr/sbin/sshd -D &
sleep 1

cd /app
exec /app/agent
