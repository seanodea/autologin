#!/bin/bash
wget 'https://bootstrap.pypa.io/get-pip.py' -O get-pip.py

sudo apt install python-pip -y || python2 get-pip.py

sudo pip2 install pexpect prettytable termcolor colored PyYAML pycrypto || sudo pip install pexpect prettytable termcolor colored PyYAML pycrypto

mkdir -p ~/
cat bashrctail > ~/.bashrc
cp al /usr/bin/
mkdir -p ~/al/
cp settings.yaml ~/.al/
cp ConEmu.xml $APPDATA/ConEmu.xml
echo ". ~/.bashrc" >> /etc/profile
. ~/.bashrc
