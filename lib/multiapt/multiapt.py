# -*- coding: utf-8 -*-
# vim: set expandtab ts=2 shiftwidth=2 list: 

import sys
import config

import getopt
import os
from Nagios import Nagios
from paramiko.client import SSHClient, MissingHostKeyPolicy
import paramiko # exception handling, misc ssh stuff
from binascii import hexlify # missing host key policy needs this
import socket # for exception handling

class Host:
  def __init__(self, name):
    self.name = name
    self.ip = None
    self.ssh_pkey = None
    self._ssh = None

  def __str__(self):
    return self.name

  def transport(self):
    """Returns the ssh transport for this host."""
    if self._ssh == None:
      self._ssh = SSHClient()
      # import keys using paramikos method
      self._ssh.load_system_host_keys()
      # import openssh system host keys
      host_keys_file = '/etc/ssh/ssh_known_hosts'
      if os.path.exists(host_keys_file):
        self._ssh.load_system_host_keys(host_keys_file)
      # import saved host keys from/for multiapt
      host_keys_file = os.getenv('HOME','/')+'/.ssh/known_hosts_multiapt'
      if os.path.exists(host_keys_file):
        self._ssh.load_host_keys(host_keys_file)
      # now set our own filename for key save purposes
      self._ssh._host_keys_filename = host_keys_file
      # enable our own policy for host key problems
      self._ssh.set_missing_host_key_policy(SSHAskHostKeyPolicy())
      if Main.debug: print 'D: ssh.connect()'
      self._ssh.connect(self.ip, username=config.remote_username, pkey=self.ssh_pkey)
    return self._ssh

class APTException(Exception):
  """
  Exception raised by generic failures from remote APT.
  """
  pass

class UnexpectedOutputException(APTException):
  pass

class UnknownPackagesException(APTException):
  pass

class Package:
  """A package, with a version."""
  def __init__(self, name, version):
    self.name = name
    self.version = version
  def __str__(self):
    return '%s [%s]' % (self.name, self.version)

class APT:
  """Encapsulates APT operations and state on remote hosts."""

  def __init__(self, host):
    self.host = host
    self.packages_needing_upgrade = []

  def _build_full_apt_cmd(self, t, commandline):
    full_cmd = 'apt-get ' + commandline
    if t.get_transport().get_username() != 'root':
      full_cmd = 'sudo -S ' + full_cmd + ' </dev/null'
    return full_cmd

  def _run_remote_apt(self, t, commandline, quiet=False):
    full_cmd = self._build_full_apt_cmd(t, commandline)
    if Main.debug:
      print 'D: apt: %s' % commandline
      quiet = False
    stdin, stdout, stderr = t.exec_command(full_cmd)
    stdin.close()
    lines = []
    for line in stdout:
      if not quiet: sys.stdout.write(">%s>> %s" % (self.host.name, line))
      lines.append(line)
      if line.startswith('E: '):
        stdout.close()
        stderr.close()
        raise APTException(line)
    for line in stderr:
      if line.startswith('Password:'):
        raise UnexpectedOutputException('Unexpected output from command "%s", possibly a misconfiguration of sudo. (Partial) Output: "%s"' % (full_cmd, line))
    return lines

  def run_inventory(self):
    """Refreshes the list of (for upgrade purposes) available packages."""
    self.cmd_update()
    self.cmd_upgrade_simul()

  def run_upgrade(self, download_only):
    """Upgrades the host."""
    self.cmd_upgrade(download_only)

  def cmd_update(self):
    """Remotely runs the apt-get update operation."""
    t = self.host.transport()
    flags = '-qq'
    if Main.debug: flags = '-q'
    self._run_remote_apt(t, 'update '+flags)

  def cmd_upgrade_simul(self):
    """Remotely runs the simulated apt-get upgrade operation."""
    t = self.host.transport()
    flags = '-qq'
    if Main.debug: flags = '-q'
    results = self._run_remote_apt(t, 'upgrade '+flags+' -s', True)
    # Inst python2.4 [2.4.4-3] (2.4.4-3+etch1 Debian-Security:4.0/stable) []
    # Inst python2.4-minimal [2.4.4-3] (2.4.4-3+etch1 Debian-Security:4.0/stable)
    # Conf python2.4-minimal (2.4.4-3+etch1 Debian-Security:4.0/stable)
    # Conf python2.4 (2.4.4-3+etch1 Debian-Security:4.0/stable)
    self.packages_needing_upgrade = []
    for line in results:
      if not line.startswith('Inst'):
        if line.startswith('Conf'):
          continue
        else:
          raise UnexpectedOutputException('Unexpected output from apt-get upgrade %s -s; (partial) text: "%s"' % (flags, line))
      l = line.split()
      p = Package(l[1], l[3].split()[0][1:])
      p.previous_version = l[2][1:-1]
      self.packages_needing_upgrade.append(p)

    for line in results:
      if line.startswith('Inst'): continue
      l = line.split()
      for p in self.packages_needing_upgrade:
        if p.name == l[1]:
          break
      else:
        raise UnknownPackagesException('apt-get upgrade would modify additional packages: "%s"' % l[1]) 
      p = Package(l[1], l[3].split()[0][1:])
 
  def cmd_upgrade(self, download_only):
    """Remotely runs the apt-get upgrade operation."""
    t = self.host.transport()
    params = 'upgrade -q -y --force-yes'
    if download_only: params = params + ' -d'
    results = self._run_remote_apt(t, params)

class Hostgroup:
  def __init__(self, name):
    self.name = name
    self.hosts = []

  @staticmethod
  def print_groups(hostgroups):
    keys = hostgroups.keys()
    keys.sort()
    for key in keys:
      hg = hostgroups[key]
      print '  %s:' % key
      print '    Packages: %s' % hg.name
      print '    Hosts: %s' % ", ".join(map(str, hg.hosts))
      print ''


class SSHAskHostKeyPolicy(MissingHostKeyPolicy):
  """
  Policy for rejecting/accepting SSH host keys, based on users
  response.
  """
  def missing_host_key(self, client, hostname, key):
    print ''
    print '-- SSH: Unknown host server key:'
    print '-- Server: %s' % hostname
    print '-- Key: %s' % hexlify(key.get_fingerprint())
    answer = raw_input('-- Accept? (yes/no): ')
    while True:
      if answer == 'yes':
        client._host_keys.add(hostname, key.get_name(), key)
        if client._host_keys_filename is not None:
          print '-- Saving host key.'
          client.save_host_keys(client._host_keys_filename)
        return
      elif answer == 'no':
        raise SSHHostKeyVerificationFailedException
      else:
        answer = raw_input('-- Please type "yes" or "no": ')

class SSHHostKeyVerificationFailedException(Exception):
  pass

class Terminal:
  @staticmethod
  def get_size(fd):
    """Gets [rows,columns] of the terminal attached to fd."""
    import struct
    import termios
    from fcntl import ioctl
    s = struct.pack('HHHH', 0, 0, 0, 0)
    x = ioctl(fd.fileno(), termios.TIOCGWINSZ, s)
    x = struct.unpack('HHHH', x)
    return (x[0], x[1])
  @staticmethod
  def clear_line(fd):
    w = Terminal.get_size(fd)[1] 
    fd.write("\r" + (" " * w))
    fd.flush()

class Main:
  """Contains the actual glue."""

  def __init__(self, argv):
    self.argv = argv
    ### Unbuffered sys.stdout
    sys.stdout = os.fdopen(1, 'w', 0)

  @staticmethod
  def main(argv):
    """Application entry point."""
    App = Main(argv)
    rc = App.parse_args()
    if rc > 0: return rc
    return App.run()

  def run(self):
    """Executes the specified command."""
    self.nagios = Nagios()

    # expand host list, if needed
    self.hosts = self.hosts.split(',')
    if self.hosts[0][0] == '%':
      def addflag(flags, f, no, v):
        flags['!'+f] = flags[f] = v
        if no:
          flags.pop(f)
        else:
          flags.pop('!'+f)

      flags = {}
      exps = self.hosts
      exps[0] = exps[0][1:]
      for exp in exps:
        n = exp[0] == '!'
        if n: exp = exp[1:]
        if exp == 'all': flags = {}
        elif exp == 'ack': addflag(flags, 'problem_has_been_acknowledged', n, 1)
        elif exp in ('crit','critical'): addflag(flags, 'current_state', n, Nagios.STATE_CRITICAL)
        elif exp in ('warn','warning'): addflag(flags, 'current_state', n, Nagios.STATE_CRITICAL)
        elif exp == 'ok': addflag(flags, 'current_state', n, Nagios.STATE_OK)
        else:
          print 'E: unknown expanѕion "%s"' % exp
          return 2
      self.hosts = self.nagios.get_host_list_by_service(config.apt_service_name, flags)
    else:
      hosts = []
      for host in self.hosts:
        hosts.append(Host(host))
      self.hosts = hosts

    print "Operating on the following hosts:"
    if len(self.hosts) == 0:
      print "None. Nothing to do, exiting!"
      return 0
    print ", ".join(map(str, self.hosts))
    print

    if Main.debug:
      import paramiko.util
      import logging
      l = logging.getLogger('paramiko')
      l.setLevel(logging.DEBUG)
      lh = logging.StreamHandler(sys.stderr)
      lh.setFormatter(logging.Formatter('%(levelname)-.3s [%(asctime)s.%(msecs)03d] thr=%(_threadid)-3d %(name)s: %(message)s','%Y%m%d-%H:%M:%S'))
      l.addHandler(lh)

    # now really do something
    if self.action == 'recheck':
      return self.cmd_recheck()
    elif self.action == 'upgrade':
      return self.cmd_upgrade()

  def parse_args(self):
    """Parse command and options from command line."""
    self.program_name = self.argv[0]

    if len(self.argv[1:]) == 0:
      return self.show_usage()

    self.action = self.argv[1]
    if self.action not in ['recheck', 'upgrade']:
      print "E: command \"%s\" not recognized." % self.action
      return 2

    try:
      opts, args = getopt.getopt(self.argv[2:], "nhdH:", ["dry-run", "help", "hosts="])
    except getopt.GetoptError, err:
      print "E: %s" % str(err) # will print something like "option -a not recognized"
      return 2

    self.hosts = config.hosts_default
    Main.debug = False
    self.dry_run = False
    self.download_only = False
    for o, a in opts:
      if o in ('-h', '--help'):
        return self.show_usage()
      elif o in ('-d'):
        self.download_only = True
      elif o in ('-D'):
        print 'D: Enable debug.'
        Main.debug = True
      elif o in ('-n', '--dry-run'):
        self.dry_run = True
      elif o in ('-H', '--hosts'):
        self.hosts = a

  def show_usage(self):
    """Prints usage information for multiapt."""
    print "multiapt."
    print "Usage: %s [options] command" % self.program_name
    print "Usage: %s [options] upgrade [packagename]" % self.program_name
    print ""
    print "Commands:"
    print "  recheck - Rechecks APT-Freshness via Nagios"
    print "  upgrade - Upgrades packages. Default: all, else: [packagename]"
    print ""
    print "Options:"
    print "  -h  - This help text."
    print "  -d  - Debug. Mostly for ssh stuff."
    print "  -n  - Just list what would be upgraded."
    print "  -H  - Host list to work on (default: %s)" % config.hosts_default
    print ""
    print "Host Expansions:"
    print "  Pass '%exp,!exp,...' to -H to expand the host list. exp:"
    print "    all: reset expansion to _all_ hosts"
    print "    ack: only acknowledged hosts"
    print "    crit: only hosts with CRITICAL service state"
    print "    warn: only hosts with WARNING service state"
    print "    ok: only hosts with OK service state"
    print "                      This multiapt has no Cow Powers."
    return 2

  def cmd_recheck(self):
    """Rechecks all hosts in Nagios."""
    status_prefix = 'Initiating recheck: '
    hosts_done = 0
    for host in self.hosts:
      Terminal.clear_line(sys.stdout)
      sys.stdout.write("\r%s[%02d/%02d] %s" % (status_prefix, hosts_done+1, len(self.hosts), host.name))
      self.nagios.reschedule_service_check(host.name, config.apt_service_name)
      hosts_done = hosts_done + 1
    Terminal.clear_line(sys.stdout)
    sys.stdout.write("\r%s[%02d/%02d] Done.\n" % (status_prefix, hosts_done, len(self.hosts)))

  def _prepare_ssh_pkey(self):
    """Tries to load config.ssh_key from file, for later use. Doesn't do that, it there are keys in the agent."""
    from paramiko.agent import Agent
    from paramiko import RSAKey, DSSKey
    import getpass
    if config.ssh_key is None:
      # user didn't configure a specific ssh_key, so nothing to do for us
      return None

    agent = Agent()
    if len(agent.get_keys()) > 0 and config.ssh_key_ignore_if_agent:
      print "I: Running ssh-agent found, not loading ssh-key %s" % config.ssh_key
      return None

    # try to load the key from file
    password = None
    need_password = False
    saved_exception = None
    for pkey_class in (DSSKey, RSAKey):
      try:
        return pkey_class.from_private_key_file(config.ssh_key, password=password)
      except paramiko.PasswordRequiredException:
        need_password = True
        break
      except paramiko.SSHException, e:
        saved_exception = e

    if need_password == False:
      print "W: Could not load ssh-key %s, ignoring. (Reason: %s)" % (config.ssh_key, saved_exception)
    else:
      # need a password
      password = getpass.getpass("SSH passphrase required for ssh-key %s: " % config.ssh_key)
      for tries in [1,2]:
        try:
          return pkey_class.from_private_key_file(config.ssh_key, password=password)
        except paramiko.SSHException:
          password = getpass.getpass("SSH passphrase required for ssh-key %s: " % config.ssh_key)
        except Exception, e:
          print "W: Could not load ssh-key %s, ignoring. (Reason: %s)" % (config.ssh_key, e)
          return None
      print "W: Ignoring ssh-key %s after 3 passphrase failures." % config.ssh_key

    return None

  def cmd_upgrade(self):
    """Upgrades all hosts."""
    from paramiko.client import SSHClient
    pkey = self._prepare_ssh_pkey()

    hostgroups = dict()
    hosts_done = []
    status_prefix = 'Inventory: '

    def handle_host_exception(host, str):
      print ' -- %s (ignoring host for further operations)' % str
      self.hosts.remove(host)

    def handle_one_host(host):
      host.ip = self.nagios.get_ip_for_host(host.name)
      host.ssh_pkey = pkey
      Terminal.clear_line(sys.stdout)
      sys.stdout.write("\r%s[%02d/%02d] %s (%s)" % (status_prefix, len(hosts_done)+1, len(self.hosts), host.name, host.ip))
      host.apt = APT(host)
      try:
        host.apt.run_inventory()
      except SSHHostKeyVerificationFailedException:
        handle_host_exception(host, 'Host key verification failed for "%s"' % host.name)
        return
      except paramiko.AuthenticationException:
        handle_host_exception(host, 'Authentication failed')
        return
      except paramiko.SSHException, e:
        handle_host_exception(host, 'SSH/Paramiko problem: %s' % e)
        return
      except APTException, e:
        handle_host_exception(host, 'APT problem: %s' % e)
        return
      except socket.error, e:
        handle_host_exception(host, 'Socket problem: "%s"' % e)
        return
      # well.
      hosts_done.append(host)
      # now categorise this host
      p_str = ", ".join(map(lambda p: '%s (%s => %s)' % (p.name, p.previous_version, p.version), host.apt.packages_needing_upgrade))
      if "-prod-" in host.name: p_str = "PROD: " + p_str
      if "-stag-" in host.name: p_str = "STAG: " + p_str
      if "-devl-" in host.name: p_str = "DEVL: " + p_str
      if p_str == '':
        # nothing to do for this host
        return
      for k in hostgroups.keys():
        if hostgroups[k].name == p_str:
          hostgroups[k].hosts.append(host)
          break
      else:
        hg = Hostgroup(p_str)
        hg.hosts.append(host)
        hostgroups['Group %d' % (len(hostgroups)+1)] = hg

    # walk through the hosts
    hosts = self.hosts[:]
    while len(hosts) > 0:
      handle_one_host(hosts.pop(0))

    # inventory is done, enter interactive mode
    print ''
    print ''

    while True:
      # enter query loop
      print 'The following upgrade groups exist:'
      Hostgroup.print_groups(hostgroups)

      if len(hostgroups) == 0:
        print "None."
        return 0
      if self.download_only:
        print 'Download-only requested.'
      if self.dry_run:
        print 'Dry-run requested, exiting.'
        return 0

      print ''
      answer = raw_input('Which groups do you want to update? (comma-seperated; incremental is possible; .=quit): ')
      if answer == '.':
        print "Ok, quitting."
        return 0
      elif answer == 'd':
        self.download_only = not self.download_only
        print "Now: download-only = %s" % self.download_only
      elif answer == '?':
        Hostgroup.print_groups(hostgroups)
        print ''
        print '  Other options:'
        print '  d: Toggle download-only (currently: %s)' % self.download_only
        print '  ?: Print hostgroups and this help'
        print '  .: Quit'
      else:
        # run upgrade for selected groups
        upgraders = {}
        for index in answer.split(','):
          try:
            indexname = 'Group %d' % int(index)
            upgraders[indexname] = hostgroups[indexname]
          except ValueError:
            print 'E: answer "%s" is not valid, ignoring' % (index)
            continue
          except KeyError:
            print 'E: group %d does not exist, ignoring' % (index)
            continue
        for indexname in upgraders.keys():
          hg = upgraders[indexname]
          print 'Upgrading %s (%s):' % (indexname, hg.name)
          for host in hg.hosts:
            print '  Upgrading host %s:' % host.name
            host.apt.run_upgrade(self.download_only)
            if not self.download_only:
              self.nagios.reschedule_service_check(host.name, config.apt_service_name)
          try:
            del hostgroups[indexname]
          except KeyError:
            print 'E: failed to remove %s from list' % indexname
        print 'Done upgrading these.'
        #print 'D: successgroups: ', success_groups
        #print 'D: hostgroups: ', hostgroups

