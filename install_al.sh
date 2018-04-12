#!/bin/bash
wget 'https://bootstrap.pypa.io/get-pip.py' -O get-pip.py

python2 get-pip.py

pip2 install pexpect prettytable termcolor colored PyYAML bcrypt

mkdir -p ~/
cat bashrctail > ~/.bashrc
cp al /usr/bin/
mkdir -p ~/al/
cp settings.yaml ~/.al/
cp ConEmu.xml $APPDATA/ConEmu.xml
echo ". ~/.bashrc" >> /etc/profile
. ~/.bashrc
