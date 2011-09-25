#!/bin/bash

# This file is altered to favor PHP developers

function check_install {
if [ -z "`which "$1" 2>/dev/null`" ]
then
executable=$1
shift
while [ -n "$1" ]
do
DEBIAN_FRONTEND=noninteractive apt-get -q -y install "$1"
print_info "$1 installed for $executable"
shift
done
else
print_warn "$2 already installed"
fi
}

function check_remove {
if [ -n "`which "$1" 2>/dev/null`" ]
then
DEBIAN_FRONTEND=noninteractive apt-get -q -y remove --purge "$2"
print_info "$2 removed"
else
print_warn "$2 is not installed"
fi
}

function check_sanity {
# Do some sanity checking.
if [ $(/usr/bin/id -u) != "0" ]
then
die 'Must be run by root user'
fi

if [ ! -f /etc/debian_version ]
then
die "Distribution is not supported"
fi
}

function die {
echo "ERROR: $1" > /dev/null 1>&2
exit 1
}

function get_domain_name() {
# Getting rid of the lowest part.
domain=${1%.*}
lowest=`expr "$domain" : '.*\.\([a-z][a-z]*\)'`
case "$lowest" in
com|net|org|gov|edu|co|my)
domain=${domain%.*}
;;
esac
lowest=`expr "$domain" : '.*\.\([a-z][a-z]*\)'`
[ -z "$lowest" ] && echo "$domain" || echo "$lowest"
}

function get_password() {
# Check whether our local salt is present.
SALT=/var/lib/radom_salt
if [ ! -f "$SALT" ]
then
head -c 512 /dev/urandom > "$SALT"
chmod 400 "$SALT"
fi
password=`(cat "$SALT"; echo $1) | md5sum | base64`
echo ${password:0:13}
}

function install_dash {
check_install dash dash
rm -f /bin/sh
ln -s dash /bin/sh
}

function install_dropbear {
check_install dropbear dropbear
check_install /usr/sbin/xinetd xinetd

# Disable SSH
touch /etc/ssh/sshd_not_to_be_run
invoke-rc.d ssh stop

# Enable dropbear to start. We are going to use xinetd as it is just
# easier to configure and might be used for other things.
cat > /etc/xinetd.d/dropbear <<END
service ssh
{
socket_type = stream
only_from = 0.0.0.0
wait = no
user = root
protocol = tcp
server = /usr/sbin/dropbear
server_args = -i
disable = no
}
END
invoke-rc.d xinetd restart
}

#function install_exim4 {
#check_install mail exim4
#if [ -f /etc/exim4/update-exim4.conf.conf ]
#then
#sed -i \
#"s/dc_eximconfig_configtype='local'/dc_eximconfig_configtype='internet'/" \
#/etc/exim4/update-exim4.conf.conf
#invoke-rc.d exim4 restart
#fi
#}

function install_sendmail {
check_install sendmail sendmail-bin
if [ -f /etc/mail/sendmail.conf ]
then
invoke-rc.d sendmail restart
fi
}

function install_mysql {
# Install the MySQL packages
check_install mysqld mysql-server
check_install mysql mysql-client

# Install a low-end copy of the my.cnf to disable InnoDB, and then delete
# all the related files.
invoke-rc.d mysql stop
rm -f /var/lib/mysql/ib*
cat > /etc/mysql/conf.d/lowendbox.cnf <<END
[mysqld]
key_buffer = 8M
query_cache_limit	= 1M
query_cache_size = 8M
skip-innodb
expire_logs_days	= 10
max_binlog_size         = 10M
END
invoke-rc.d mysql start

# Generating a new password for the root user.
passwd=`get_password root@mysql`
mysqladmin password "$passwd"
cat > ~/.my.cnf <<END
[client]
user = root
password = $passwd
END
chmod 600 ~/.my.cnf
}

function install_nginx {
check_install nginx nginx

# Need to increase the bucket size for Debian 5.
cat > /etc/nginx/conf.d/lowendbox.conf <<END
server_names_hash_bucket_size 64;
END

# Sites that have multiple .php file entry points (nginx > 0.7.27)
cat > /etc/nginx/php.conf <<END
index index.html index.php;

try_files \$uri @missing;

# Route all requests for non-existent files to index.php
location @missing {
rewrite ^ /index.php\$request_uri last;
}

# Pass PHP scripts to php-fastcgi listening on port 9000
location ~ \.php {
include fastcgi_params;
fastcgi_pass 127.0.0.1:9000;
}
END

# MVC frameworks with only a single index.php entry point (nginx > 0.7.27)
cat > /etc/nginx/php.mvc.conf <<END
index index.html index.php;

try_files \$uri @missing;

location @missing {
rewrite ^ /index.php\$request_uri last;
}

# This will only run if the below location doesn't, so anything other than /index.php
location ~ \.php {
rewrite ^ /index.php\$request_uri last;
}

# Only send index.php requests to PHP-fastcgi
location ^~ /index.php {
include fastcgi_params;
fastcgi_pass 127.0.0.1:9000;
}
END

echo 'Created /etc/nginx/php.mvc.conf and /etc/nginx/php.conf files for PHP sites'
echo 'To use them "include" them in your /etc/nginx/sites-enabled/[site] config'
echo ' '

invoke-rc.d nginx restart
}

function install_php {
# PHP core
check_install php5-cgi php5-cgi
check_install php5-cli php5-cli

# PHP modules
DEBIAN_FRONTEND=noninteractive apt-get -y install php-apc php5-suhosin php5-curl php5-gd php5-mcrypt php5-mysql php5-sqlite php5-xcache

# Create startup script
cat > /etc/init.d/php-fastcgi <<"END"
#!/bin/bash
### BEGIN INIT INFO
# Provides: php-fastcgi
# Required-Start: networking
# Required-Stop: networking
# Default-Start: 2 3 4 5
# Default-Stop: 0 1 6
# Short-Description: Start the PHP FastCGI processes web server.
### END INIT INFO

BIND=127.0.0.1:9000
USER=www-data
PHP_FCGI_CHILDREN=8
PHP_FCGI_MAX_REQUESTS=1000

PHP_CGI=/usr/bin/php-cgi
PHP_CGI_NAME=`basename $PHP_CGI`
PHP_CGI_ARGS="- USER=$USER PATH=/usr/bin PHP_FCGI_CHILDREN=$PHP_FCGI_CHILDREN PHP_FCGI_MAX_REQUESTS=$PHP_FCGI_MAX_REQUESTS $PHP_CGI -b $BIND"
RETVAL=0

start() {
echo -n "Starting PHP FastCGI: "
start-stop-daemon --quiet --start --background --chuid "$USER" --exec /usr/bin/env -- $PHP_CGI_ARGS
RETVAL=$?
echo "$PHP_CGI_NAME."
}
stop() {
echo -n "Stopping PHP FastCGI: "
killall -q -w -u $USER $PHP_CGI_NAME
RETVAL=$?
echo "$PHP_CGI_NAME."
}

case "$1" in
start)
start
  ;;
stop)
stop
  ;;
restart)
stop
start
  ;;
*)
echo "Usage: php-fastcgi {start|stop|restart}"
exit 1
  ;;
esac
exit $RETVAL
END

echo 'Created /etc/init.d/php-fastcgi startup script which spawns 8 PHP processes'
echo ' '

# Make it executable
chmod 755 /etc/init.d/php-fastcgi

# load on statup
update-rc.d php-fastcgi defaults
invoke-rc.d php-fastcgi start
}

function install_iptables {

check_install iptables

if [ -z "$1" ]
then
die "Usage: `basename $0` iptables <ssh-port-#>"
fi

# Create startup rules
cat > /etc/iptables.up.rules <<END
*filter

# http://articles.slicehost.com/2010/4/30/ubuntu-lucid-setup-part-1

# Allows all loopback (lo0) traffic and drop all traffic to 127/8 that doesn't use lo0
-A INPUT -i lo -j ACCEPT
-A INPUT ! -i lo -d 127.0.0.0/8 -j REJECT

# Accepts all established inbound connections
-A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allows all outbound traffic
# You can modify this to only allow certain traffic
-A OUTPUT -j ACCEPT

# Allows HTTP and HTTPS connections from anywhere (the normal ports for websites)
-A INPUT -p tcp --dport 80 -j ACCEPT
-A INPUT -p tcp --dport 443 -j ACCEPT

# IF YOU USE INCOMMING MAIL UN-COMMENT THESE!!!

# Allows POP (and SSL-POP)
#-A INPUT -p tcp --dport 110 -j ACCEPT
#-A INPUT -p tcp --dport 995 -j ACCEPT

# SMTP (and SSMTP)
#-A INPUT -p tcp --dport 25 -j ACCEPT
#-A INPUT -p tcp --dport 465 -j ACCEPT

# IMAP (and IMAPS)
#-A INPUT -p tcp --dport 143 -j ACCEPT
#-A INPUT -p tcp --dport 993 -j ACCEPT

# Allows SSH connections (only 3 attempts by an IP every 2 minutes, drop the rest to prevent SSH attacks)
-A INPUT -p tcp -m tcp --dport $1 -m state --state NEW -m recent --set --name DEFAULT --rsource
-A INPUT -p tcp -m tcp --dport $1 -m state --state NEW -m recent --update --seconds 120 --hitcount 3 --name DEFAULT --rsource -j DROP
-A INPUT -p tcp -m state --state NEW --dport $1 -j ACCEPT

# Allow ping
-A INPUT -p icmp -m icmp --icmp-type 8 -j ACCEPT

# log iptables denied calls
-A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables denied: " --log-level 7

# Reject all other inbound - default deny unless explicitly allowed policy
-A INPUT -j REJECT
-A FORWARD -j REJECT

COMMIT
END

# Set these rules to load on startup
cat > /etc/network/if-pre-up.d/iptables <<END
#!/bin/sh
/sbin/iptables-restore < /etc/iptables.up.rules
END

# Make it executable
chmod +x /etc/network/if-pre-up.d/iptables

# Load the rules
iptables-restore < /etc/iptables.up.rules

# You can flush the current rules with /sbin/iptables -F
echo 'Created /etc/iptables.up.rules and startup script /etc/network/if-pre-up.d/iptables'
echo 'If you make changes you can restore the rules with';
echo '/sbin/iptables -F'
echo 'iptables-restore < /etc/iptables.up.rules'
echo ' '
}

# Store the starting package list for comparison later
function base_packages {
dpkg --get-selections > packages.txt
}

# dotdeb has nginx +1.0
function install_dotdeb {

# Don't install them twice!
if grep -q "dotdeb" /etc/apt/sources.list; then
die "dotdeb is already in /etc/apt/sources.list"
fi

# Add the dotdeb sources
cat >> /etc/apt/sources.list <<END
# dotdeb has latest stable nginx
deb http://packages.dotdeb.org stable all
deb-src http://packages.dotdeb.org stable all
END

# Install dotdeb GPG key
wget http://www.dotdeb.org/dotdeb.gpg
cat dotdeb.gpg | apt-key add -
rm dotdeb.gpg

echo 'Installed dotdeb in /etc/apt/sources.list'
echo ' '
}

function install_phpmyadmin(
check_install phpmyadmin phpmyadmin
# creating symlink for phpmyadmin in default nginx vhost
ls -s /usr/share/phpmyadmin /usr/share/nginx/www
chown root:root -R /usr/share/nginx/www/*
)

function install_vnstat(
check_install vnstat vnstat
if [ ! -d /usr/share/nginx/www/vnstat ]
then
# change the version from vnstat frontend website http://www.sqweek.com/
wget http://www.sqweek.com/sqweek/files/vnstat_php_frontend-1.5.1.tar.gz
tar zxf /usr/share/nginx/www/vnstat_php_frontend-1.5.1.tar.gz
mv /usr/share/nginx/www/vnstat_php_frontend-1.5.1 /usr/share/nginx/www/vnstat
rm -rf /usr/share/nginx/www/vnstat_php_frontend-1.5.1
chown root:root -R /usr/share/nginx/www/*
fi
)
function install_syslogd {
# We just need a simple vanilla syslogd. Also there is no need to log to
# so many files (waste of fd). Just dump them into
# /var/log/(cron/mail/messages)
check_install /usr/sbin/syslogd inetutils-syslogd
invoke-rc.d inetutils-syslogd stop

for file in /var/log/*.log /var/log/mail.* /var/log/debug /var/log/syslog
do
[ -f "$file" ] && rm -f "$file"
done
for dir in fsck news
do
[ -d "/var/log/$dir" ] && rm -rf "/var/log/$dir"
done

cat > /etc/syslog.conf <<END
*.*;mail.none;cron.none -/var/log/messages
cron.* -/var/log/cron
mail.* -/var/log/mail
END

[ -d /etc/logrotate.d ] || mkdir -p /etc/logrotate.d
cat > /etc/logrotate.d/inetutils-syslogd <<END
/var/log/cron
/var/log/mail
/var/log/messages {
rotate 4
weekly
missingok
notifempty
compress
sharedscripts
postrotate
/etc/init.d/inetutils-syslogd reload >/dev/null
endscript
}
END

invoke-rc.d inetutils-syslogd start
}

function install_wordpress {
check_install wget wget
if [ -z "$1" ]
then
die "Usage: `basename $0` wordpress <hostname>"
fi

# Downloading the WordPress' latest and greatest distribution.
mkdir /tmp/wordpress.$$
wget -O - http://wordpress.org/latest.tar.gz | \
tar zxf - -C /tmp/wordpress.$$
mv /tmp/wordpress.$$/wordpress "/var/www/$1"
rm -rf /tmp/wordpress.$$
chown root:root -R "/var/www/$1"

# Setting up the MySQL database
dbname=`echo $1 | tr . _`
userid=`get_domain_name $1`
# MySQL userid cannot be more than 15 characters long
userid="${userid:0:15}"
passwd=`get_password "$userid@mysql"`
cp "/var/www/$1/wp-config-sample.php" "/var/www/$1/wp-config.php"
sed -i "s/database_name_here/$dbname/; s/username_here/$userid/; s/password_here/$passwd/" \
"/var/www/$1/wp-config.php"
mysqladmin create "$dbname"
echo "GRANT ALL PRIVILEGES ON \`$dbname\`.* TO \`$userid\`@localhost IDENTIFIED BY '$passwd';" | \
mysql

# Setting up Nginx mapping
cat > "/etc/nginx/sites-enabled/$1.conf" <<END
server {
server_name $1;
root /var/www/$1;
include /etc/nginx/fastcgi_php;
location / {
index index.php;
if (!-e \$request_filename) {
rewrite ^(.*)$ /index.php last;
}
}
}
END
invoke-rc.d nginx reload
}


function install_domain {

if [ -z "$1" ]
then
die "Usage: `basename $0` domain <hostname.tld>"
fi

# Don't allow this to happen twice
if [ -d "/var/www/$1" ]; then
die "Site $1 already exists"
fi

# If the www directory does not exist
if [ ! -d "/var/www" ]; then
mkdir "/var/www"
fi

# If the www/log directory does not exist
if [ ! -d "/var/www/log" ]; then
mkdir "/var/www/log"
fi

# Make the site directory and site log directory
mkdir "/var/www/$1"
mkdir "/var/www/log/$1"

# Setting up the MySQL database
dbname=`echo $1 | tr . _`
userid=`get_domain_name $1`
# MySQL userid cannot be more than 15 characters long
userid="${userid:0:15}"
passwd=`get_password "$userid@mysql"`
mysqladmin create "$dbname"
echo "GRANT ALL PRIVILEGES ON \`$dbname\`.* TO \`$userid\`@localhost IDENTIFIED BY '$passwd';" | \
mysql

# Save the new MySQL user/pass in a file in that directory
echo "Created $userid ($passwd) with all permissions on $dbname"

# Create sample database script
cat > "/var/www/$1/index.php" <<END
<?php
\$db = new PDO('mysql:host=localhost;dbname=$dbname', '$userid', '$passwd');
\$db->exec("CREATE TABLE IF NOT EXISTS `test` (`name` varchar(100)) ENGINE=MyISAM");
\$result = \$db->query("SHOW TABLES");
while (\$row = \$result->fetch()) { var_dump(\$row); }
END

# PHP needs permission to access this
chown www-data:www-data -R "/var/www/$1"

# Setting up Nginx mapping
cat > "/etc/nginx/sites-enabled/$1.conf" <<END
server {
listen 80;
server_name $1;
root /var/www/$1;
access_log /var/www/log/$1/access.log;
error_log /var/www/log/$1/error.log;
include /etc/nginx/php.mvc.conf;
}
END
invoke-rc.d nginx reload

echo "Created /var/www/$1, /var/www/log/$1, and /etc/nginx/sites-enabled/$1.conf"
echo ' '

}


function print_info {
echo -n -e '\e[1;36m'
echo -n $1
echo -e '\e[0m'
}

function print_warn {
echo -n -e '\e[1;33m'
echo -n $1
echo -e '\e[0m'
}

function remove_unneeded {
# Some Debian have portmap installed. We don't need that.
check_remove /sbin/portmap portmap

# Remove rsyslogd, which allocates ~30MB privvmpages on an OpenVZ system,
# which might make some low-end VPS inoperatable. We will do this even
# before running apt-get update.
check_remove /usr/sbin/rsyslogd rsyslog

# Other packages that seem to be pretty common in standard OpenVZ
# templates.
check_remove /usr/sbin/apache2 'apache2*'
check_remove /usr/sbin/named bind9
check_remove /usr/sbin/smbd 'samba*'
check_remove /usr/sbin/nscd nscd

# Need to stop sendmail as removing the package does not seem to stop it.
#if [ -f /usr/lib/sm.bin/smtpd ]
#then
#invoke-rc.d sendmail stop
#check_remove /usr/lib/sm.bin/smtpd 'sendmail*'
#fi

# Need to stop exim4 as removing the package does not seem to stop it.
if [ -f /usr/lib/exim4/exim4 ]
then
invoke-rc.d exim4 stop
check_remove /usr/lib/exim4/exim4 'exim4*'
fi
}

function update_upgrade {
# Run through the apt-get update/upgrade first. This should be done before
# we try to install any package
apt-get -q -y update
apt-get -q -y upgrade
}

########################################################################
# START OF PROGRAM
########################################################################
export PATH=/bin:/usr/bin:/sbin:/usr/sbin

check_sanity
case "$1" in
dotdeb)
install_dotdeb
;;
system)
remove_unneeded
update_upgrade
base_packages
;;
optimize)
install_dropbear
install_dash
install_syslogd
;;
iptables)
install_iptables $2
;;
mysql)
install_mysql
;;
nginx)
install_nginx
;;
php)
install_php
;;
domain)
install_domain $2
;;
#exim4)
#install_exim4
#;;
sendmail)
install_sendmail
;;
vnstat)
install_vnstat
;;
phpmyadmin)
install_phpmyadmin
;;
wordpress)
install_wordpress $2
;;
*)
# Explain each Option
echo 'Usage:' `basename $0` '[option] [argument]'
echo 'Available options (in recomended order):'
echo ' - dotdeb (install dotdeb apt source for nginx +1.0)'
echo ' - system (remove unneeded, upgrade system)'
echo ' - optimize (install dash, dropbear, and syslogd)'
echo ' - iptables (setup basic firewall with HTTP(S) open)'
echo ' - mysql (install MySQL and set root password)'
echo ' - nginx (install nginx and create sample PHP configs)'
echo ' - php (install PHP 5 with APC, GD, cURL, suhosin, mcrypt, memcached,xcache and PDO MySQL)'
echo ' - domain (create /etc/nginx/sites-enabled/[HOST], /var/www/[HOST], and MySQL database)'
#echo ' - exim4 (install exim4)'
echo ' - sendmail (install Sendmail)'
echo ' - vnstat (install vnstat and vnstat frontend)'
echo ' - phpmyadmin (install PHPMyAdmin)'
echo ' - wordpress (install latest wordpress, create database, and setup wp-config.php)'
echo ' '

#for option in dotdeb system optimize iptables mysql nginx php domain exim4 wordpress
#do
# echo ' -' $option
#done
;;
esac