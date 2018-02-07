# split-gpg2.py
# Copyright (C) 2018 Michał "rysiek" Woźniak <rysiek@hackerspace.pl>
# Based on split-gpg2.rb (C) 2014 HW42 <hw42@ipsumj.de>
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License along
# with this program; if not, write to the Free Software Foundation, Inc.,
# 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.

# Part of split-gpg2.
#
# This implements the server part. See README for details.

import subprocess

# 
# Error handling
#
class SplitGPGException(Exception):
  
  # see gpg-error.h
  SOURCE_SHIFT = 24
  SOURCE_GPGAGENT = 4
  ERR_USER_1 = 1024
  ERR_ASS_UNKNOWN_CMD = 275
  
  UNKNOWN_IPC_COMMAND = SOURCE_GPGAGENT << SOURCE_SHIFT | ERR_ASS_UNKNOWN_CMD

class GPGAgentException(SplitGPGException):
  pass
  
class StartFailed(GPGAgentException):
  pass
  
class GetSockPathFailed(GPGAgentException):
  pass
  
class ProtocolError(GPGAgentException):
  pass
  
class CommandFilteredException(GPGAgentException):
  def __init__(self):
    self.code =  self.SOURCE_GPGAGENT << self.SOURCE_SHIFT | self.ERR_USER_1
    self.message = "Command filtered by split-gpg2."


# from assuan.h
ASSUAN_LINELENGTH = 1002


class Server:
  
  default_commands = {
    'RESET': command_RESET,
    'OPTION': command_OPTION,
    'AGENT_ID': command_AGENT_ID,
    'HAVEKEY': command_HAVEKEY,
    'KEYINFO': command_KEYINFO,
    'GENKEY': command_GENKEY,
    'SIGKEY': command_SIGKEY,
    'SETKEY': command_SETKEY,
    'SETKEYDESC': command_SETKEYDESC,
    'PKDECRYPT': command_PKDECRYPT,
    'SETHASH': command_SETHASH,
    'PKSIGN': command_PKSIGN,
    'GETINFO': command_GETINFO,
    'BYE': command_BYE
  }
  
  default_options = {
    # should be overriden on startup to reflect sensible values
    'ttyname': ['fake', 'OK'],
    'ttytype': ['fake', 'OK'],
    'display': ['override', ':0'],
    'lc-ctype': ['fake', 'OK'],
    'lc-messages': ['fake', 'OK'],
    'allow-pinentry-notify': ['verify', None],
    'agent-awareness': ['verify', '2.1.0']
  }
  
  default_timer_delay = {
    'PKSIGN': None,  # always query for signing
    'PKDECRYPT': 300 # 5 min
  }
  
  default_hash_algos = {
    2: {'name': 'sha1', 'len': 40},
    3: {'name': 'rmd160', 'len': 40},
    8: {'name': 'sha256', 'len': 64},
    9: {'name': 'sha384', 'len': 96},
    10: {'name': 'sha512', 'len': 128},
    11: {'name': 'sha224', 'len': 56}
  }
  
  # cin - client input IO-object
  # cout - client output IO-object
  # client_domain - name of the connected client vm
  def __init__(self, cin, cout, client_domain):
    self.cin = cin
    self.cout = cout
    self.client_domain = client_domain

    self.cin.sync = true
    self.cout.sync = true
    
    # prevent unicode parsing bugs
    self.cin.set_encoding('ASCII-8BIT:ASCII-8BIT')
    self.cout.set_encoding('ASCII-8BIT:ASCII-8BIT')
    
    self.options = self.default_options
    self.hash_algos = self.default_hash_algos
    self.timer_delay = self.default_timer_delay
    self.verbose_notifications = false
    
    connect_agent()
    
  
  def connect_agent(self):
    if subprocess.call(['gpgconf', '--launch', 'gpg-agent']) != 0:
      raise StartFailed
      
    
    
