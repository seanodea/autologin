#!/usr/bin/env python
''' al.py
Licsense: BSD 3.0
Author: Chris Godwin <seanodea@github.com>

This is to soften the login process to linux servers.
Will be linux centric, but will seek to run on Windows
supporting putty. This will also apply for netsec if the
need arises.

More Information in the ReadMe'''

import os
import time
import re
import sys
import shutil
import yaml
from Crypto.PublicKey import RSA
from Crypto import Random
from os.path import expanduser
from termcolor import colored

home = expanduser("~")
confdir = home + "/.al"

keyFile = "mykey.pem"

if not os.path.isdir(confdir): os.mkdir(confdir)
try:
	f = open(confdir + '/' + keyFile,'r')
	key = RSA.importKey(f.read())
except:
	key = RSA.generate(2048)
	f = open(confdir + '/' + keyFile,'w')
	f.write(key.exportKey('PEM'))
	f.close()

with open(confdir + "/settings.yaml", 'r') as yamlstream:
    try:
	settings = yaml.load(yamlstream)
    except yaml.YAMLError as exc:
        print(exc)

'''Configuration:
	The Login() class can be configured through many
	variables, although, the goal of this project is to
	automate login for the purpose of ease, simplicity,
	and as fewest road blocks as	possible, configuration
	being one of them.

loginTimeout:
	The amount of time in seconds we should let ssh
	run with out giving us a repsonse
	
sessionTimeout:
	The blanket amount of time fed to the pexpect
	method for expectng responses. This script uses a
	continuos loop and is designed to expect text in any
	event. This avoids proceedual errors involving is and is not
	logic. 
	
altHomeDir:
	The directory you'd like al to use instead of
	$HOME when reading/writing cookies, credentials,
	and logs. If this variable is set and the directory is
	now writable, it will default to $HOME. If that
	environment variable is not set or is not writeable
	it will default to /tmp. If all three directories are ether
	not set, not writable, or unavailable, then fix that and
	try again.
	
	Default: ~/
'''	
class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
	
class Login():
	'''This is the main class that handles login functions
	and variables. Call to initate the login process for
	servers in argv.'''
	
	def __init__(self):
		''' This is the class organizer. When initiated, it
		declares all variables, and calls the methods.'''

		try:
			if os.access(os.environ['HOME'], os.W_OK): home = os.environ['HOME'] # If we can use it, just $HOME
			if os.access(settings['altHomeDir'], os.W_OK): home = settings['altHomeDir'] # finally, lets overwrite if user has specified what to use		
		except NameError:
			pass # If altHomeDir isn't declared or set, move on with my life
		except KeyError:
			pass # Ignore(don't set) errors if $HOME env isn't set
		
		self.declareVars()	# Declare all of the variables used in class.
		(options, args) = self.checkArgs(sys.argv)

		self.debug = options.debug

		try:
			argn = args[1:]
			revargs = argn[::-1]
			self.serverID = revargs[0].lower()
		except IndexError, e:
			self.eWarn('Error with with args')
			sys.exit(7)

		self.collectServerInfo(self.serverID)
		if not os.path.isdir(home + settings['logDir']): os.mkdir(home + settings['logDir'])
		self.logFile = home + settings['logDir'] + '/' + str(self.serverID) + '.log'		# Set the log for all transactions'''
		try:
			shutil.move(self.logFile,self.logFile + "." + str(time.time()))
		except:
			pass
		try:
			self.session(self.mode)			# Controlling method, loops forever untill it gets what it wants
		except KeyboardInterrupt:
			self.session('close')
		sys.exit(1)
	def checkArgs(self, args):
		''' Method to determine that the correct amount
		of arguments were used on the command line'''

		import optparse
		usage="usage: %prog [options]\nusage: %prog [options] servername"

		parser = optparse.OptionParser(usage=usage)
		parser.add_option("-D", "--debug",action="store_true", dest="debug", default=False,help="Print debug messages to the screen before connection.")
		parser.add_option("-l", "--list",action="store_true", dest="list_servers", default=False,help="List stored servers and exit.")
		parser.add_option("-k", "--copykey", action="store_true", dest="copy_key", default=False,help="Copy ssh keys to the authorized_keys file of the destination server.")
		parser.add_option("-j", "--pubfile", dest="pub_key_file", default="~/.id_rsa.pub",help="Specify a keyfile to copy. Used with -k",metavar="FILE")
		parser.add_option("-K", "--keyfile", dest="key_file", default="~/.id_rsa.key",help="Specify a keyfile to copy. Used with -k",metavar="FILE")
		parser.add_option("-t", "--timeout", dest="timeout", default=settings['loginTimeout'], help="Set the console attach timeout to N seconds.", metavar="N")
		parser.add_option("-u", "--user", dest="user", default=False,help="Specify an ssh user.")
		parser.add_option("-i", "--ip", dest="ip", default=False,help="Specify an ip address.")
		parser.add_option("-p", "--port", dest="port", default=22,help="Specify a port number. Default 22.")
		parser.add_option("-d", "--del", dest="delete_server", default=False,help="Remove stored server SERVERNAME and exit.", metavar="SERVERNAME")
		parser.add_option("-a", "--add", dest="add_server", default=False,help="Add stored server SERVERNAME and exit.", metavar="SERVERNAME")
		parser.add_option("-b", "--gw", dest="gw", default=False,help="Use one of the stored servers as a gw server.",metavar="SERVERNAME")
		parser.add_option("-P", "--password", dest="password", default=False,help="Override the stored password or store a password from commandline.")
		parser.add_option("-s", "--nosudo",action="store_true", dest="nosudo", default=False,help="Do not sudo once logged in.")
		parser.add_option("-c", "--command", dest="command", default=False,help="Run this command and exit.")
		parser.add_option("-C", "--chpw", action="store_true", dest="change_password", default=False,help="change passwords")
		(options, args) = parser.parse_args(args)
		self.options = options

		# Case switcher
		self.port = options.port
		self.command = options.command
		if options.delete_server and options.add_server:
			self.eWarn("Can't add and delete.")
			sys.exit(0)
		if options.delete_server:
			self.mode = 'del'
		elif options.add_server:
			self.mode = 'add'
		elif options.change_password:
			self.mode = 'chpw'
		else:
			self.mode = 'conn'

		self.port = options.port
		global sessionTimeout
		settings['sessionTimeout'] = int(options.timeout)
		self.list_servers = options.list_servers
		self.sshPubKeyFile = options.pub_key_file
		self.sshKeyFile = options.key_file
		self.useSSHKey = self.copy_key
		self.host['password'] = options.password

		if options.delete_server:
			return (options, args)
		elif options.add_server:
			return (options, args)
		if options.list_servers:
			self.printServers(args)
			return (options, args)
		elif len(args) == 0:
			self.printUsageOrMenu(args)
		return (options, args)
	def declareVars(self):
		''' Method to declare or set all of the varaibles used in the 
		script that need to be set first so they can be used in
		conditional comparisons '''

		# Declare inits and constants
		self.options			= False
		self.host			= {}
		self.debug			= False
		self.list_servers		= False
		self.copy_key			= False
		self.timeout			= 0
		self.port			= str()
		self.useSSHKey			= False
		self.sshKeyPassphrase		= False
		self.isSuper			= False
		self.throughgw			= False
		self.connectto			= None
		self.gwlogin			= None
		self.usegw			= None
		self.mode			= 'conn'
		self.timeoutcount		= 0
		self.ehlosent			= False
	def printUsageOrMenu(self, args):
		''' Print proper usage and exit. '''
		print "run al -h"
		sys.exit(0)
	def printServers(self, args):
		''' Print proper usage and exit. '''
		from os import listdir
		from os.path import isfile, join
		from prettytable import PrettyTable

		t = PrettyTable(["Server", "IP", "User", "Password","Gateway"])
		t.align["Server"] = "l" # Left align city names
		t.padding_width = 1 # One space between column edges and contents (default)
		onlyfiles = [f for f in listdir(confdir) if isfile(join(confdir, f))]
		onlyfiles.remove(keyFile)
		self.eInfo('Accessing host configs')
		for file in onlyfiles:
			with open(confdir + "/" + file, 'r') as yamlstream:
				try:
					self.host = yaml.load(yamlstream)

					# decrypt
					plainpw = key.decrypt(self.host['password'])
					self.host['password'] = plainpw.replace('\n',"")

					hosttag = file.replace('.yaml','')
					if self.host['gw']:
						gwString = self.host['gw']
					else:
						gwString = "none"
					t.add_row([hosttag, self.host['ip'],self.host['username'],self.host['password'],gwString])
				except yaml.YAMLError as exc:
					print(exc)
				except KeyError, e:
					pass
				except TypeError, e:
					self.eWarn('Error with file: ' + file)
					pass
		print t
		sys.exit(0)
	def collectServerInfo(self, serverID):
		'''This code collects the server info interactively'''

		try:
			with open(confdir + "/" + serverID + ".yaml", 'r') as yamlstream:
				try:
					self.connectto = yaml.load(yamlstream)
					# set it up so that if the pw is missing, its replaced by the gws.
					if not self.connectto['password']:
						self.connectto['password'] = self.host['password']

					if len(self.connectto['gw']) > 0:
						self.eInfo('Accessing host configs: ~/.al/%s.yaml ~/.al/%s.yaml' % (self.serverID, self.connectto['gw']))
						with open(confdir + "/" + self.connectto['gw'] + ".yaml", 'r') as gwyamlstream:
							try:
								self.host = yaml.load(gwyamlstream)
								self.usegw = True
							except yaml.YAMLError as exc:
								print(exc)
					else:
						self.eInfo('Accessing host config: ~/.al/%s.yaml' % serverID)
						self.host = self.connectto
						self.usegw = False
				except yaml.YAMLError as exc:
					print(exc)
			# decrypt destination host
			plainpw = key.decrypt(self.connectto['password'])
			self.connectto['password'] = plainpw.replace('\n',"")

			# decrypt gw if there is one
			if self.connectto['gw']:
				plainpw = key.decrypt(self.host['password'])
				self.host['password'] = plainpw.replace('\n',"")

			if settings['hidepw']:
				dispassword = 'XXXXXXXX'
			else:
				dispassword = self.host['password']
		except IOError as err:
			self.addNewHost()
		self.eInfo('Host settings: ssh://' + self.host['username'] + ':' + dispassword + '@' + self.serverID + ':' + str(self.host['port']))
	def addNewHost(self):
		try:
			self.host = {}
			self.host['ip'] = str(self.options.ip) if self.options.ip else str(re.sub("[^a-zA-Z0-9\.]", "", str(raw_input('Enter the IP address for ' + str(self.serverID) +': '))))
			self.host['port'] = None
			if not self.options.port:
				while self.host['port'] is None:
					try:
						self.host['port'] = self.options.port if self.options.port else int(raw_input('Enter port for ' + self.serverID +'[22]: ') or '22')
					except:
						print "Lets try that again, please enter a number."
						self.host['port'] = self.options.port if self.options.port else int(raw_input('Enter port for ' + self.serverID +'[22]: ') or '22')
			else:
				self.host['port'] = self.options.port
			if not self.host['port']:
				self.host['port'] = 22

			self.host['username'] = self.options.user if self.options.user else raw_input('Enter the user for ' + self.serverID +': ')
			self.host['password'] = self.options.password if self.options.password else raw_input('Enter the password ONLY ONCE for ' + self.serverID +': ')
			# encrypt
			public_key = key.publickey()
			enc_data = public_key.encrypt(self.host['password'], 32)
			self.host['password'] = enc_data

			self.host['sudopw'] = raw_input('Use a password after sudo [(on)/off]?: ')
			self.host['gw'] = raw_input('Enter the gateway through which we connect to ' + self.serverID + '[Blank for none]')
			self.host['gwtype'] = raw_input('RDP or ssh gateway?' + self.serverID + '[SSH/win]')

			if self.host['gwtype'] == '':
				self.host['gwtype'] = 'ssh'
		except KeyboardInterrupt, e:
			sys.exit(0)

		if self.host['sudopw'] == 'off':
			self.host['sudopw'] = False
		else:
			self.host['sudopw'] = True
		self.host['hostname'] = self.serverID
		self.host['gw'] = ''
		self.host['sudo'] = True

		with open(confdir + "/" + self.serverID + ".yaml", 'w') as outfile:
			yaml.dump(self.host, outfile, default_flow_style=False)
		print "Wrote to " + confdir + "/" + self.serverID + ".yaml" + ", have a look. Try running al " + self.host['hostname'] + " to login automatically."
		sys.exit(0)

	def session(self, mode=''):
		''' This begins the expect/ssh session. It also listens for any of the expected text. '''
		import pexpect

		cmd = '/usr/bin/ssh'
		cmdArgs = ['-o','NumberOfPasswordPrompts=1','-o','StrictHostKeyChecking=no','-o','UserKnownHostsFile=/dev/null','-l',self.host['username'], self.host['ip'],'-p', str(self.host['port'])]
		if self.useSSHKey:
			cmdArgs.append('-i')
			cmdArgs.append(self.sshKeyFile)

		def expector(pattern,p):
			''' expector() is fed strings to expect by session() '''
			global sessionTimeout
			try:
				stat = p.expect(pattern, settings['sessionTimeout'])
				self.eDebug('Expector State: ' + str(stat))
				return stat
			except pexpect.EOF,  e:
				self.eDebug('The SSH process has died unexpectedly,\nplease check ' + self.logFile + ' for details.')
			except pexpect.ExceptionPexpect, e:
				self.eDebug('The SSH process has died unexpectedly,\nplease check ' + self.logFile + ' for details.')
		def userInteract(message):
			''' This method attaches the shell when root is fully logged in. '''
			try:
				self.eDebug(message)
				p = self.p
				#p.sendcontrol('l')
				p.interact()
				p.close()
				sys.exit(0)


			except OSError,  e:
				self.eWarn('ssh is gone. Where did it go?')
				self.eFatal(str(e), 7)
		def foundPrompt():
			''' This detects shell prompts and issues instruction based on the result. '''

			if self.connectto['gw']:
				if self.connectto['gwtype'] != 'ssh':
					print "Run `mstsc.exe -v:" + str(self.connectto['ip']) + " /F -console'"
					print "Then run `putty.exe --username " + self.connectto['username'] +" --password " + self.connectto['password'] + "--server " + str(self.connectto['ip'] + "'")
					sys.exit(0)
				if self.gwlogin != 2:
	                        	self.cmdSSH = 'ssh -o NumberOfPasswordPrompts=1 -o StrictHostKeyChecking=no -oUserKnownHostsFile=/dev/null -l ' + self.connectto['username'] + ' ' + str(self.connectto['ip']) + ' -p ' + str(self.connectto['port']) + '; exit'
					self.cmdMSTSC = '/cygdrive/c/windows/system32/mstsc.exe'
					self.eDebug('Logged into gw, issueing command: ' + self.cmdSSH) 
					self.p.sendline(self.cmdSSH)
					self.gwlogin = 2
					return True
				else:
					self.eDebug('Handling any matches, setting up session.')
					setUpSession()
					return True
			else:
				setUpSession()
		def setUpSession():
			''' This detects shell prompts and issues instruction based on the result. '''

			if self.command:
				self.eDebug('[Command Mode] Issueing command: ' + self.command) 
				self.p.sendline(self.command + '; exit')
				self.p.sendcontrol('d')
				self.p.sendcontrol('d')
			else:
				self.p.sendline(settings['ehlo'])
			userInteract('Attaching console as ' + self.host['username'])
			return True

		def sendPassword():
			try:
				if self.gwlogin != 2:
					self.p.sendline(self.host['password'])
					self.eDebug('sending '+self.host['password'])
					if ((self.options.nosudo == False and self.host['sudo'] != False) and self.host['username']!='root' and self.host['username']!='prosys') and self.isSuper == False and (self.connectto['gw'] == ''):
						self.eDebug('Becoming superuser on host.')
						self.p.sendline('sudo su -')
						if self.host['sudopw'] == True:
							self.p.sendline(self.host['password'])
							self.eDebug('sending '+self.host['password'])
						self.isSuper = True
					return True
				else:
					self.p.sendline(self.connectto['password'])
					self.eDebug('sending '+self.connectto['password'])
					if self.connectto['sudo'] == True and self.options.nosudo == False and self.connectto['username']!='root' and self.connectto['username']!='prosys' and self.isSuper == False and (self.connectto['gw'] == '' or self.gwlogin == 2):
						self.eDebug('Becoming superuser host beyond gateway.')
						self.p.sendline('sudo su -')
						if self.connectto['sudopw'] == True:
							self.p.sendline(self.connectto['password'])
							self.eDebug('sending '+self.connectto['password'])
						self.isSuper = True
					return True
			except:
				pass
		def changePassword():
			''' This method will send the user or admin password depending on the order which it is called. '''
			try:
                        	answer = raw_input("Enter a new password:")
				plainpw = answer.replace('/n','')
				try:
					self.p.sendline(plainpw)
					self.p.sendline(plainpw)
				except:
					pass
				changeMe = raw_input("Change stored password for " + self.host['username'] + "[y/N]:")
				self.host['password'] = plainpw
	                        # encrypt
        	                public_key = key.publickey()
                	        enc_data = public_key.encrypt(plainpw, 32)
                        	self.host['password'] = enc_data
				if changeMe=="Y" or changeMe=="y":
					with open(confdir + "/" + self.serverID + ".yaml", 'w') as outfile:
						yaml.dump(self.host, outfile, default_flow_style=False)
					print "Wrote to " + confdir + "/" + self.serverID + ".yaml" + ", have a look. Try running `al " + self.serverID + "' to login automatically."
					sys.exit(0)
				else:
					print "Exiting. Change your pw manually."
					sys.exit(5)
                	except KeyboardInterrupt:
                        	sys.exit(0)
		def expectClose(p,n):
				self.eDebug('Not dead yet: expectclose')				
				if not p.terminate():
					p.terminate(force=True)	
				p.close(p)
				if n:
					return False
				else:
					sys.exit(0)
		def sendEhlo():
			# This sends the ehlo, then if it fires again, timeouts are happening, it breaks out of them after 4 loops.
			self.timeoutcount = self.timeoutcount + 1
			self.p.sendline('echo eh""lo')
			if self.timeoutcount > 4:
				sys.exit(0)
		def startSession():
			''' This spawns the session, sets the log file, and informs the user '''
			spawnArgs = ''
			
			for i in cmdArgs:
				spawnArgs = spawnArgs + ' ' + str(i)
			self.eDebug('Running command '+os.path.basename(cmd)+' with args '+spawnArgs)
	
			try:
				
				import signal
				self.eInfo('Logging @ %s' % self.logFile)
				self.p = pexpect.spawn(cmd, cmdArgs,settings['loginTimeout'], 156,  2000,  file(self.logFile, settings['logMode']))
				p = self.p
				self.sigwinch_passthrough(0, 0)							# Go ahead and winch the window effectively setting the initial size
				signal.signal(signal.SIGWINCH, self.sigwinch_passthrough)			# If TIOCGWINSZ then change the window size
				signal.signal(signal.SIGHUP, lambda: expectClose(self.p,0))			# If HUP then close ssh too
				p.delaybeforesend = 0.3
				'''p.logfile = sys.stdout'''
				'''p.logfile = file(self.logFile, settings['logMode'])'''
				
			
			except pexpect.ExceptionPexpect, e:
				self.eFatal(str(e), 99)
				
			except IOError, e:
				if e.errno == 13: self.eDebug('Error setting transaction log: %s %s' % (e.strerror, e.filename))
			
			expectNodes = [
				'(?i)Connection refused',										# 0
				'(?i)no route to host|(?i)Name or service not known',							# 1
				'Offending key in (?i)', 										# 2
				'(?i)are you sure you want to continue connecting',							# 3
				'[Nn]ew\s.*\s[Pp]assword:.*',											# 4
				'(.*[Pp]assword:.*)',											# 5
				'.*[Pp]ermission denied.*',										# 6
				'(?i)terminal type',											# 7
				'su:\suser\sroot\sdoes\snot\sexist.*', 									# 8
				'.*Authentication\sfailure.*\r\n|.*su:\sSorry.*\r\n|.*su:\sincorrect\spassword.*',			# 9
				'(.*ehlo.*)',												# 10
				'notusedanymore',											# 11
				'notusedanymore',											# 12
				'(?i)there are stopped jobs',										# 13
				'Connection to (?i) closed.',										# 14
				'^.*passphrase\sfor\skey.*\r\n', 									# 15
				pexpect.TIMEOUT,											# 16
				]
				
			
			switcher = {
				0			: lambda: self.eFatal('The connection was refused!', 1),
				1			: lambda: self.eFatal(self.p.after, 2),
				2			: lambda: self.eFatal('Offending key in file ' + self.p.after), 
				3			: lambda: self.p.sendline('yes'),
				4			: changePassword,
				5			: sendPassword,
				6			: lambda: self.eFatal('Password was not accepted! Try running `al -C ' + self.serverID + '\' to change the password. Check gateway configs."',3),
				7			: lambda: self.p.sendline('ansi'),
				8			: lambda: userInteract('Attached as '+self.host['username']+'. Cannot Become super user :('),
				9			: lambda: userInteract('Password was rejected, Try running `al -C' + self.serverID + '\' to change the password. Check gateway configs."'),
				10			: foundPrompt, # host or gw
				11			: foundPrompt, # host through gw
				12			: foundPrompt, # prosys ksh user
				13			: lambda: self.p.sendline(self.host['passphrase']), 
				14			: userInteract,
				17			: userInteract,
				None			: lambda: self.eDebug('Breakout case.',True)
				}
				
			def connectToServer():
				while True:
					time.sleep(0.01)
					switcher.get(expector(expectNodes,self.p), lambda: sendEhlo())()
			if mode == 'close':
				self.p.close()
				sys.exit(0)
			if mode == 'add':
				self.addNewHost()
			if mode == 'del':
				raw_input("Enter to continue, ctrl + c to bail")
				os.remove(confdir + "/" + self.serverID + ".yaml")
				print "Deleted " + confdir + "/" + self.serverID + ".yaml"
				sys.exit(0)
			if mode == 'chpw':
				changePassword()

			connectToServer()
		startSession()
	def eFatal(self,message,exitCode):
		''' This method reports text errors and exits with
		the pertaining exit code. '''
		print colored(message, 'red')
		if settings['pressEnterToExit']: a = raw_input('Press enter to exit!\n')
		sys.exit(exitCode)
		
	
	def eWarn(self,message):
		''' This prints out non fatal warnings the user might
		need to know about. '''
		print colored(message, 'yellow')
		return True
	def eDebug(self,message,exit=False):
		''' This prints out non fatal warnings the user might
		need to know about. '''
		if self.debug == 1: print colored(message, 'cyan')
		if exit != True:
			return True
		else:
			sys.exit(0);
	def eInfo(self,message):
		''' This prints out important information '''
		print colored(message, 'green')
		return True	
	def sigwinch_passthrough (self,sig,data):
		""" A method to pass TIOCGWINSZ(terminal i/o change window size) signals(not env vars) to the ssh session.\
		This allows realtime resizing of applications, editors, top, ncurses menues, and pretty much anything that is resident.\
		
		For unknown reasons, the crucial function called within this method, time.sleep(0.6), prevents the\
		window from toppling the entire class. Crashes commonly occur while resizing a session running top, watch, tail, etc.\
		This behaviour is mostly observed when resizing to small row/column counts."""
		import struct, fcntl, termios
		s = struct.pack("HHHH", 0, 0, 0, 0)
		q = struct.unpack('hhhh', fcntl.ioctl(sys.stdout.fileno(), termios.TIOCGWINSZ , s))
		time.sleep(0.6)
		
		try:
			self.p.setwinsize(q[0],q[1])
			
		
		except OSError, e:
			self.eDebug('failed ose when set termsize') 
			pass
			
		
		except:
			self.eDebug('failed ose when set termsize!')
			pass

if __name__ == "__main__":
	a=Login()
	a.session('close')
	sys.exit(0)
