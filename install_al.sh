#!/bin/bash

if [[ "$OSTYPE" == "linux-gnu" ]]; then
        # ...
        if [ -f /etc/redhat-release ]; then
          sudo yum install sshpass y
          sudo yum -y install python-pip
        fi

        if [ -f /etc/lsb-release ]; then
          sudo apt-get install sshpass -y
          sudo apt-get install python-pip -y
        fi


elif [[ "$OSTYPE" == "darwin"* ]]; then
        # Mac OSX
	brew install https://raw.githubusercontent.com/kadwanev/bigboybrew/master/Library/Formula/sshpass.rb
	wget 'https://bootstrap.pypa.io/get-pip.py' -O get-pip.py
	sudo python get-pip.py
elif [[ "$OSTYPE" == "cygwin" ]]; then
        # POSIX compatibility layer and Linux environment emulation for Windows
	sudo apt-cyg install sshpass -y
	wget 'https://bootstrap.pypa.io/get-pip.py' -O get-pip.py
	sudo python get-pip.py
elif [[ "$OSTYPE" == "freebsd"* ]]; then
        echo "Install ssh pass manually"
	wget 'https://bootstrap.pypa.io/get-pip.py' -O get-pip.py
	sudo python get-pip.py
fi
        sudo pip install pexpect prettytable termcolor colored PyYAML pycrypto


mkdir -p ~/
cat bashrctail >> ~/.bashrc
cp al /usr/bin/
mkdir -p ~/.al/
cp settings.yaml ~/.al/
. ~/.bashrc
