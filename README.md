# Autologin - By @seanodea
## BSD 3.0 Liscense Copyright 2015-2017 Chris Godwin

# Automaticall Manages Interactive Logins
## Manages encrypted credentials
## Connects directly or Tunnels thru SSH Gateways
Autologin can do the following:
* Handles window resizing
* Automatically log in via ssh
* Run a command on a remote system and return the output (great with for loops!)
* Run a command on several systems with al_multi command.
* Automagically hop through Linux Gateways
* Automagically hop through Windows Gateways(not yet, but soon!)
* Store server information in yaml files
* Log your ssh sessions
* Log into entire environments at once, even through gateways
* Run aliases for your favorite commands

## Usage

Run `al web1` to login to web1
>On the first run you'll encounter input quesetions about the server if there is no yaml on file for that server.

Run `al web1 -c 'rpm -qa | grep wis'` to see what rpms are installed.
>This will run the command and retun the output to the screen. Useful for running puppet agent -t in for loop.

Run `al_multi web1 arrwapp1 arrwboapp1` to open new console tabs logging into those systems.
>Log into an entire environment

Run `al_multi_cmd web1 arrwapp1 arrwboapp1 'rpm -qa | grep wis'` to open several consols running the commands and displaying the output. 
>Log into an entire environemnt at once and run the command on every system.

Run `al -h` for other options.

## Installation:

1. Visit the autologin download page https://github.com/seanodea/autologin/releases
2. Click Source Code and Download the Zip
3. Extract the folder in the zip to your Downloads Folder
4. Visit the folder and run install_al.bat and follow the instructions for Cygwin
4. Install WSL or use it in linux by running the install_al.sh
5. Launch ComEmu64 from the Start menu, and use ctrl+F12 to hide and unhide the bash terminal
6. Run al SERVERNAME, it'll collect the base server information and die, run it again and it'll login.
7. Run al_multi SERVERNAME1 SERVERNAME2 SERVERNAME3 to launch an entire environment at once.

## Configuration:

There is a settings.yaml file that will go into the ~/.al folder, open it and play with it. Server configs are located in ~/.al/servername.yaml (i.e. ~/.al/web1.yaml). The configs are straight forward:

```yaml
hostname: 'web1'
ip: 'web1'
username: 'seanodea'
password: >
  XXXXXX <-- this is encrypted after collected
port: 22
gw: 'rengw2'
gwtype: 'ssh'
sudo: True
```

```yaml
hostname: The hostname is used for functional purposes.
ip: The ip is used in the ssh command and can be a hostname.
password: encrypted password of the user
gw: hostname of the gateway to login through, for non cat and prod set to empty string (eg: gw: '')
gwtype: either 'ssh' or 'win'. 'win' and mstsc launches coming soon
sudo: True/False
sudopw: True/False
```

### Todo:
- [ ] come up with todos
