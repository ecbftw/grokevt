#
# Copyright (C) 2005 Timothy D. Morgan
#
# This program is free software; you can redistribute it and/or
# modify it under the terms of the GNU General Public License
# as published by the Free Software Foundation version 2 of the
# License.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# $Id$

import sys
import os
import re
import struct
import anydbm

################################################################################
# String Formatting Functions

# Reference:
#  http://blogs.msdn.com/oldnewthing/archive/2004/03/15/89753.aspx
def binSIDtoASCII(sid_str):
   auth = ((ord(sid_str[2])<<40)
           | (ord(sid_str[3])<<32)
           | (ord(sid_str[4])<<24)
           | (ord(sid_str[5])<<16)
           | (ord(sid_str[6])<<8)
           | ord(sid_str[7]))
   result = "S-%d-%d" % (ord(sid_str[0]), auth)
   rest = sid_str[8:]
   for i in range(0,ord(sid_str[1])):
       if len(rest) >= 4:
           next_int = struct.unpack('<I', rest[:4])[0]
           rest = rest[4:]
           result = "%s-%d" % (result, next_int)

   return result


# Returns a string which contains s, except for non-printable or
# special characters are quoted in hex with the syntax '\xQQ' where QQ
# is the hex ascii value of the quoted character.  specials must be a
# sequence.
def quoteBinaryInString(s, specials="\\"):
    ret_val = ''
    for c in str(s):
        if (ord(c) < 32) or (ord(c) > 126) or (c in specials):
            ret_val += ("\\x%.2X" % ord(c))
        else:
            ret_val += c

    return ret_val


# Reference:
#  http://msdn.microsoft.com/library/en-us/winui/winui/windowsuserinterface/resources/strings/stringreference/stringfunctions/wsprintf.asp
#
# returns a formatted string.
def wsprintf(fmt, vars):
    # Python's string formatting is very close to wsprintf's.  Just a
    # few types need to be converted to get a close approximation of
    # proper behavior. 

    # XXX: However, as this isn't 100% compliant with the spec, it
    # should be re-written as a state-machine to be fully correct.
    
    optionals = r'(-?#?0?[0-9]*[.]?[0-9]*)'

    # S,ls,lS,hs,hS => s
    py_fmt = re.sub('%'+optionals+'[lh]{0,1}[sS]',
                    r'%\1s', fmt)
    
    # lu,li,ld,hu,hi,hd => d
    py_fmt = re.sub('%'+optionals+'[lh][uid]',
                    r'%\1d', py_fmt)

    # lc,lC,C => c
    py_fmt = re.sub('%'+optionals+'l{0,1}[cC]',
                    r'%\1c', py_fmt)

    # lx => x; lX => X
    py_fmt = re.sub('%'+optionals+'l([xX])',
                    r'%\1\2', py_fmt)

    # p => d
    py_fmt = re.sub('%'+optionals+'p',
                    r'%\1d', py_fmt)

    return (py_fmt % vars)


# Reference:
#  http://msdn.microsoft.com/library/en-us/debug/base/formatmessage.asp
#  XXX: Does someone know of a better reference for this?  The author of
#       that page couldn't write themselves out of a wet paper bag.  Way
#       too much ambiguity.
def formatMessage(fmt, vars):
    # states:
    # 0: normal text
    # 1: in escape sequence
    # 3: in format string
    state=0
    ret_val=''
    arg_num=''
    arg_index = None
    extended_fmt = ''
    for c in fmt:
        if state == 0:
            if c == '%':
                state=1
            else:
                ret_val += c
        elif state == 1:
            if len(arg_num) == 0:
                if ord(c) > 0x2f and ord(c) < 0x3a:
                    arg_num = c
                elif c in ('%', ' ', '.', '!'):
                    ret_val += c
                    state = 0
                elif c == 'n':
                    ret_val += '\x0a'
                    state = 0
            elif len(arg_num) == 1:
                if ord(c) > 0x2f and ord(c) < 0x3a:
                    arg_index = int(arg_num + c) - 1
                else:
                    arg_index = int(arg_num) - 1
                    
                    if c == '!':
                        state = 3
                        extended_fmt = '%'
                    else:
                        if arg_index < len(vars):
                            if c == '%':
                                ret_val += "%s" % vars[arg_index]
                                state = 1
                                arg_num = ''
                            else:
                                ret_val += "%s%s" % (vars[arg_index], c)
                                state = 0
                                arg_num = ''
                        else:
                            # arg_num not in vars
                            if c == '%':
                                ret_val += "%%%s" % arg_num
                                state = 2
                                arg_num = ''
                            else:
                                ret_val += "%%%s%s" % (arg_num, c)
                                state = 0
                                arg_num = ''
        elif state == 3:
            if c == '!':
                state = 0
                ret_val += wsprintf(extended_fmt, vars[arg_index])
            else:
                extended_fmt += c
                
    return ret_val



################################################################################
# Message database wrapper

class messageRepository:
    svc_dbs = {}
    msg_dbs = {}
    def __init__(self, topdir, log):
        msg_dir = "%s/messages" % topdir
        dbs = os.listdir(msg_dir)
        for db in dbs:
            db_file = "%s/%s" % (msg_dir,db)
            self.msg_dbs[db] = anydbm.open(db_file, "r", 0644)

        log_dir = "%s/services" % topdir
        for t in ("category", "event", "parameter"):
            db_file = "%s/%s/%s.db" % (log_dir, log, t)
            self.svc_dbs[t] = anydbm.open(db_file, "r")
   
         
    def getMessageTemplate(self, service, rva):
        ret_val = None
        mdbs = self.svc_dbs["event"].get(service.lower(), None)
        if mdbs:
            for mdb in mdbs.split(':'):
                ret_val = self.msg_dbs[mdb].get(rva, None)
                if ret_val:
                    break
      
        return ret_val



################################################################################
# Configuration wrapper

class grokevtConfig:
    path_vars = {}
    drive_mapping = {}
    registry_path = ''
    profile_path = ''

    def __init__(self, config_dir, profile):
        # Non-profile-specific configs would be read here (if there were any).
        
        self.profile_path = "%s/systems/%s" % (config_dir,profile)
        
        # XXX: the os.access() call may not work correctly in suid situations.
        if not os.path.isdir(self.profile_path)\
               or not os.access(self.profile_path, os.R_OK):
            sys.stderr.write("WARNING: Could not read profile"\
                             +" directory '%s'.\n" % dir)
        else:
            self.registry_path = self.readLineFromFile("%s/system-registry"
                                                       % self.profile_path)
            self.path_vars = self.readMappingFromFiles("%s/path-vars"
                                                       % self.profile_path)
            self.drive_mapping = self.readMappingFromFiles("%s/drives"
                                                           % self.profile_path)
    
    def readMappingFromFiles(self, dir):
        ret_val = {}
        # XXX: the os.access() call may not work correctly in suid situations.
        if os.path.isdir(dir) and os.access(dir, os.R_OK):
            for k in os.listdir(dir):
                l = self.readLineFromFile("%s/%s" % (dir, k))
                if l != None:
                    ret_val[k] = l
        else:
            sys.stderr.write("WARNING: Could not read configuration"\
                             +" directory '%s'.\n" % dir)
        return ret_val
    
    
    def readLineFromFile(self, fp):
        ret_val = None
        # XXX: the os.access() call may not work correctly in suid situations.
        if os.path.isfile(fp):
            if os.access(fp, os.R_OK):
                f = file(fp, "r")
                ret_val = f.readline().rstrip('\n\r')
                f.close()
            else:
                sys.stderr.write("WARNING: Could not read configuration"\
                                 +" file '%s'.\n" % fp)
        
        return ret_val


################################################################################
### Below this line are build-time settings. ###
