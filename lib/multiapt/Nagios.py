# -*- coding: utf-8 -*-

import urllib
import multiapt
import config

class Nagios:
  """Various tools for querying/manipulating Nagios."""
  STATE_OK = 0
  STATE_WARNING = 1
  STATE_CRITICAL = 2

  def get_host_list_by_service(self, service_name, flags = {'problem_has_been_acknowledged': 0}):
    """Retrieves a (plain) list of hosts, which have a service called service_name, and flags match exactly.
    
    Example:
    get_host_list_by_service('APT-Freshness', {'problem_has_been_acknowledged': 0, 'current_state': Nagios.STATE_CRITICAL})
    """
    in_service_block = False
    hosts = list()

    def flag_compare(flag, service, flags):
      b = flags[flag]
      if flag[0] == '!':
        a = service[flag[1:]]
        return a == b
      else:
        a = service[flag]
        return not a == b

    # read in service definitions from retention.dat file, one block at a time
    for line in open(config.nagios_statusdat, 'r'):
      if 'servicestatus {' in line:
        in_service_block = True
        service = dict()
        continue
      if '}' in line:
        # now do something with this service
        if in_service_block and service.has_key('service_description') and service['service_description'] == service_name:
          # compare service flags
          if len(filter(lambda flag: flag_compare(flag, service, flags), flags.keys())) == 0:
            if config.nagios_filter_hostnames:
              if config.nagios_filter_hostnames(service['host_name']):
                hosts.append(multiapt.Host(service['host_name']))
            else:
              hosts.append(multiapt.Host(service['host_name']))
        in_service_block = False
        continue
      if in_service_block:
        key,value = line.strip().split("=",1)
        # need special int() for integer values
        try:
          value = int(value)
        except ValueError: pass
        service[key] = value

    return hosts

  def get_ip_for_host(self, host_name):
    """Retrieves the IP Address for a given host."""
    in_host_block = False
    for line in open(config.nagios_objectcache, 'r'):
      line = line.strip()
      if line.startswith('define host {'):
        in_host_block = True
      elif line == '}':
        in_host_block = False
      elif in_host_block:
        if line.startswith("host_name\t") and not line.split()[1] == host_name:
          in_host_block = False
          continue
        if line.startswith("address\t"):
          return line.split()[1]
    raise ValueError


  def reschedule_service_check(self, host_name, service_name):
    """Reschedules a service check immediately."""
    f = urllib.urlopen(config.nagios_cmdcgiurl + '?cmd_typ=7&cmd_mod=2&start_time=1970-01-01%2001:01:01&force_check=1&btnSubmit=Commit&host=' + host_name + '&service=' + service_name)
    f.read()
    # should probably check for success/failure and raise
    f.close()



