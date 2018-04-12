@echo off
set PATH=C:\cygwin64\bin;%PATH%

echo Installing ConEmu

ConEmuSetup.161206.exe /passive

set /p DUMMY= When Conemu stops, choose 64bit version, press enter...

echo Installing Cygwin Automatically
START /WAIT setup-x86_64.exe ^
--packages ^
bind-utils,^
git,^
git-cvs,^
git-svn,^
gitk,^
python,^
python-appindicator,^
python-cairo,^
python-dbus,^
python-gconf2,^
python-gi,^
python-gi-common,^
python-gobject,^
python-gtk2.0,^
python-keybinder,^
python-numpy,^
python-pexpect,^
python-pynotify,^
python-setuptools,^
python-vte,^
python-xdg,^
python3,^
rsync,^
ruby,^
ruby-json,^
ruby-rake,^
ruby-rdoc,^
rubygems,^
subversion,^
subversion-perl,^
subversion-tools,^
wget,^
zip

set /p DUMMY= When cygwin stops, press enter...

echo Installing bash components
echo on
c:\cygwin64\bin\bash.exe install_al.sh

set /p DUMMY= All Done, press enter and run ConeEMU64, then run al -h...
