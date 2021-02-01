
### Install seclist with additional dictionary

- [seclists](https://github.com/danielmiessler/SecLists) is a collection of multiple types of lists used during security assessments, collected in one place.
- [golang](https://golang.org/) is an open source programming language that makes it easy to build simple, reliable, and efficient software.
- [python3-pip](https://pypi.org/project/pip/) is the package installer for Python3.

Tools:

- [fuff](https://github.com/ffuf/ffuf): Fast web fuzzer written in Go.
- jsubfinder
- qsreplace
- [gobuster](https://github.com/OJ/gobuster): Tool used to brute-force URIs, DNS subdomains, Vhost and S3 buckets
- [o-saft](https://github.com/OWASP/O-Saft): Tool used to lists information about remote target's SSL certificate and tests the remote target according given list of ciphers.
- [Parsenmap]
- [XSSer](https://github.com/epsylon/xsser):

Hyperion

```bash
# Installing pip setuptools
pip install setuptools
pip3.9 install setuptools

# Upgrading pip 3.9, 3.8
/usr/bin/python3.9 -m pip install --upgrade pip
/usr/bin/python3 -m pip install --upgrade pip

sudo apt update
sudo apt -y install seclists gobuster golang python3-pip tnscmd10g

# Installing qsreplace
cd ~/scripts/git/
go get -u github.com/tomnomnom/qsreplace

# Installing jsubfinder
cd ~/scripts/git/
go get -u github.com/hiddengearz/jsubfinder

# Installing fuff 
cd ~/scripts/git/
git clone https://github.com/ffuf/ffuf
cd ffuf
go get
go build

# Installing XSSer
sudo pip3 install pycurl bs4 pygeoip gobject cairocffi selenium
cd ~/scripts/git/
git clone https://github.com/epsylon/xsser
cd ~/scripts/git//xsser/

# Installing O-Saft
sudo apt -y install o-saft ibidn11-dev libidn2-0-dev libzip-dev libsctp-dev libkrb5-dev
cd /usr/share/o-saft
wget https://raw.githubusercontent.com/OWASP/O-Saft/master/contrib/install_openssl.sh
sh install_openssl.sh --m

# Installing Parsenmap
cd ~/scripts/git/
git clone https://github.com/R3dy/parsenmap.git
cd parsenmap/
bundle install
ln -s ~/git/parsenmap/parsenmap.rb ~/scripts/bin/parsenmap

# Installer Hyperion
cd ~/scripts/
wget https://github.com/nullsecuritynet/tools/raw/master/binary/hyperion/release/Hyperion-2.2.zip
unzip Hyperion-2.2.zip
i686-w64-mingw32-c++ Hyperion-2.2/Src/Crypter/*.cpp -o hyperion.exe

# Installing EyeWitness
cd ~/scripts/git/
git clone https://github.com/FortyNorthSecurity/EyeWitness
cd EyeWitness/Python/setup
chmod +700 setup.sh
./setup.sh
ln -s ~/EyeWitness/Python/EyeWitness.py ~/scripts/bin/EyeWitness

# Installing BlindElephant
cd ~/scripts/git/
git clone https://github.com/lokifer/BlindElephant
cd BlindElephant
cd src
python2 setup.py install
# Should be there /usr/local/bin/BlindElephant.py

# Installing KeePass
sudo apt install libmono-system-xml-linq4.0-cil libmono-system-data-datasetextensions4.0-cil libmono-system-runtime-serialization4.0-cil mono-mcs mono-complete keepass2

# Installing Webshot

# The Ming C Compiler


sudo apt install python3-pip

mkdir /usr/share/seclists/Dictionary
wget https://raw.githubusercontent.com/derekchuank/high-frequency-vocabulary/master/30k.txt
mv 30k.txt /usr/share/seclists/Dictionary/english_dictionary30k.txt

# Installing smtp-user-enum
/root/.local/bin/pip3.8 install smtp-user-enum


# Installing GDB


https://stackoverflow.com/questions/18345763/installing-requests-module-in-python-2-7-windows



python2 -m pip install --upgrade pip setuptools wheel

```