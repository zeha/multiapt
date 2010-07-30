# -*- coding: utf-8 -*-

# Python is nice to us: everything starting with an underscore (_) is /not/
# imported into other modules.

# We will now set up the _program default_ configuration

nagios_statusdat = '/var/cache/nagios3/status.dat'
nagios_objectcache = '/var/cache/nagios3/objects.cache'
nagios_cmdcgiurl = 'http://localhost/cgi-bin/nagios3/cmd.cgi'
nagios_filter_hostnames = None
apt_service_name = 'APT-Freshness'

hosts_default = '%!ack,!ok'

"""Specifies the username for ssh. Set to None to use the current unix username."""
remote_username = None

"""SSH key to use for remote servers. Set to None if you already use an ssh agent."""
ssh_key = None

"""Ignore ssh_key if a running agent has at least one key?"""
ssh_key_ignore_if_agent = True

