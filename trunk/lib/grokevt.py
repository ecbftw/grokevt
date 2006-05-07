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
# vi:set tabsize=4:
# $Id$

import sys
import os
import time
import types
import re
import struct
import anydbm


################################################################################
# Constants

# This information provided by:
#   http://technet2.microsoft.com/WindowsServer/en/Library/7e77c2f0-8835-4bea-b972-26edb2aceb3d1033.mspx
eventTypeEnum = {0:'Success',
                 1:'Error',
                 2:'Warning',
                 4:'Information',
		 8:'SuccessAudit',
		 16:'FailureAudit'}

# XXX: this probably never changes, but might be interesting to see if
#      it is big endian on NT Alpha systems.
source_encoding = 'utf-16le'

# This is what we store message in when ripped from DLLs
template_encoding = 'utf-8'

# This is what we use if unicode output is enabled
output_encoding = 'utf-8'


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
def quoteString(s, specials="\\"):
    ret_val = ''
    for c in s:
        o = ord(c)
        if (o < 32) or (o > 126) or (c in specials):
            ret_val += ("\\x%.2X" % o)
        else:
            ret_val += c
    
    return ret_val


def quoteUnicode(s, specials=u'\\\r\n'):
    ret_val = u''
    for c in s:
        if c in specials:
            ret_val += "\\x%.2X" % ord(c)
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
# .evt log files

class evtFile:
    # useful constants
    cursor_magic = "\x11\x11\x11\x11\x22\x22\x22\x22"\
                 + "\x33\x33\x33\x33\x44\x44\x44\x44"
    header_size = 0x30
    cursor_size = 0x28
    
    # instance state
    f = None
    header = None
    cursor_offset = None
    cursor = None


    # Constructor for evtFile instances
    # Opens a log file and an associated message repository.
    # Optionally parses the .evt file's meta records (header and cursor).
    # 
    # Raises: IOError, EOFError
    # Resulting offset:
    #    (error thrown)                      --> UNDEFINED
    #    (parse_meta == 0)                   --> 0
    #    (parse_meta == 1 && missing cursor) --> 0x30
    #    (parse_meta == 1 && found cursor)   --> self.cursor['first_off']
    #
    def __init__(self, filename, message_repository, parse_meta=1):
        self.f = file(filename, "r")
        self.mr = message_repository
        if parse_meta:
            # First parse header
            if(self.guessRecordType() != 'header'):
                # XXX: use different exception class here
                raise ValueError, "File header is not an event log header."
            self.header = self.getHeaderRecord()

            # Next, try to find the cursor
            self.f.seek(self.header['next_off'])
            if(self.guessRecordType() != 'cursor'):
                sys.stderr.write("WARNING: Header does not point "\
                                +"to cursor record.\n")
                sys.stderr.write("WARNING: Searching for cursor manually...\n")

                # XXX: This is kinda ugly.
                #      Perhaps the whole file should be mmapped from the
                #      beginning?
                self.f.seek(0)
                s = self.f.read()
                self.f.seek(0)

                if s.count(self.cursor_magic) > 1:
                    sys.stderr.write("WARNING: Multiple cursors may exist."\
                                    +"  Attempting to use last one in file.\n")

                # Search for the cursor magic and attempt to validate the record
                magic_off = s.rfind(self.cursor_magic)
                if magic_off > 3:
                    self.f.seek(magic_off-4)
                while (self.guessRecordType() != 'cursor'):
                    magic_off = s.rfind(self.cursor_magic, magic_off-1)
                    if magic_off > 3:
                        self.f.seek(magic_off-4)
                    elif magic_off == -1:
                        break
                s = None
                
                if magic_off == -1:
                    sys.stderr.write("WARNING: Could not find cursor record.\n")
                    self.f.seek(0x30)
                else:
                    self.cursor_offset = magic_off-4
                    self.f.seek(self.cursor_offset)
                    self.cursor = self.getCursorRecord()
                    
            else:
                self.cursor_offset = self.header['next_off']
                self.cursor = self.getCursorRecord()
            
            self.f.seek(self.cursor['first_off'])


    def tell(self):
        return self.f.tell()
    
    
    def seek(self, off, whence=0):
        self.f.seek(off, whence)
    
    
    # XXX: is there a cleaner way to do this?
    def size(self):
        cur_pos = self.f.tell()
        self.f.seek(0, 2)
        ret_val = self.f.tell()
        self.f.seek(cur_pos)

        return ret_val


    def guessRecordType(self):
        if not self.f:
            raise IOError, "Log file not open."
        
        cur_pos = self.f.tell()
        ret_val = 'unknown'
        
        (size1,) = struct.unpack('<I', self.f.read(4))
        if(size1 >= 28):
            self.f.seek(size1-8,1)
            (size2,) = struct.unpack('<I', self.f.read(4))
            if(size2 == size1):
                self.f.seek(4-size1,1)
                if(size1 == 0x30):
                    magic = self.f.read(4)
                    if(magic == "\x4c\x66\x4c\x65"):
                        ret_val = 'header'
                
                elif(size1 == 0x28):
                    magic = self.f.read(16)
                    if(magic == self.cursor_magic):
                        ret_val = 'cursor'
                        
                else:
                    magic = self.f.read(4)
                    if(magic == "\x4c\x66\x4c\x65"):
                        ret_val = 'log'
    
        self.f.seek(cur_pos)
        return ret_val


    # Parses a header record starting at the current log file offset
    # Resulting file offset will be set to the next record on success,
    # but is undefined if an exception is raised.
    #
    # Returns: a dictionary of header values
    # Raises: IOError, EOFError
    def getHeaderRecord(self):
        fmt = '<IIIIIIIIIIII'
        fmt_len = struct.calcsize(fmt)
        raw_rec = self.f.read(fmt_len)
        
        if len(raw_rec) < fmt_len:
            raise EOFError, "Record read is too short for format."

        (size1,lfle,unknown1,unknown2,
         first_off,next_off,next_num,first_num,
         file_size,flags,retention,size2) = struct.unpack(fmt, raw_rec)

        flag_dirty   =  flags & 0x1
        flag_wrapped = (flags & 0x2) >> 1
        flag_logfull = (flags & 0x4) >> 2
        flag_primary = (flags & 0x8) >> 3
        
        ret_val = {'first_off':first_off, 'first_num':first_num,
                   'next_off':next_off, 'next_num':next_num,
                   'file_size':file_size, 'retention':retention,
                   'flag_dirty':flag_dirty, 'flag_wrapped':flag_wrapped,
                   'flag_logfull':flag_logfull, 'flag_primary':flag_primary}
        return ret_val


    # Parses a cursor record starting at the current log file offset
    # Resulting file offset will be set to the next record on success,
    # but is undefined if an exception is raised.
    #
    # Returns: a dictionary of cursor values
    # Raises: IOError, EOFError
    def getCursorRecord(self):
        fmt = '<IIIIIIIIII'
        fmt_len = struct.calcsize(fmt)
        raw_rec = self.f.read(fmt_len)

        if len(raw_rec) < fmt_len:
            raise EOFError, "Record read is too short for format."
        
        (size1,magic1,magic2,magic3,magic4,
         first_off,next_off,next_num,first_num,
         size2) = struct.unpack(fmt, raw_rec)

        ret_val = {'first_off':first_off, 'first_num':first_num,
                   'next_off':next_off, 'next_num':next_num}
        return ret_val


    # Parses a log record starting at the current log file offset
    # Resulting file offset will be set to the next record on success,
    # but is undefined if an exception is raised.
    #
    # Returns: a dictionary of log record values
    # Raises: IOError
    def getLogRecord(self):
        size_str = self.f.read(4)
        if len(size_str) < 4:
            raise EOFError, "Couldn't read record length"
        (size,) = struct.unpack('<I', size_str)
    
        fixed_fmt = '<IIIIHHHHHHIIIIII'
        fixed_fmt_len = struct.calcsize(fixed_fmt)

        rec_str = self.f.read(size-4)
        if len(rec_str) < fixed_fmt_len:
            print "fixed_fmt_len,len(rec_str): %d, %d" % (fixed_fmt_len,len(rec_str))
            raise EOFError, "Couldn't read fixed-length portion of record."
        
        variable_str_len = len(rec_str) - fixed_fmt_len
        (lfle,msg_num,
         date_created,date_written,
         event_id,event_rva_offset,
         event_type,strcount,
         category,unknown,
         closing_record_number,string_offset,
         sid_len,sid_offset,
         data_len,data_offset,
         variable_str) = struct.unpack("%s%ds" % (fixed_fmt, variable_str_len),
                                       rec_str)
        # Grab template variables
        strs = []
        if string_offset > 0:
            strs=rec_str[string_offset-4:data_offset-4].decode(
                source_encoding,'replace').split(u'\x00')
            
        # Grab source and computer fields
        vstr = variable_str.decode(source_encoding,
                                   'replace').split(u'\x00', 2)
        source = ''
        if len(vstr) > 0:
            source = vstr[0]
      
        computer = ''
        if len(vstr) > 1:
            computer = vstr[1]
        vstr = None
      
        # Grab SID
        sid = 'N/A'
        if sid_len > 0:
            sid_str = rec_str[sid_offset-4:sid_offset+sid_len-4]
            sid = binSIDtoASCII(sid_str)

        # Grab binary data chunk
        data = ''
        if data_len > 0:
            data = rec_str[data_offset-4:data_offset+data_len-4]
    
        # Retrieve and process message template
        event_rva = "%.8X"%(long(event_rva_offset)<<16|event_id)
        message_template = self.mr.getMessageTemplate(source, event_rva)
        message = ''
        if message_template:
            message = formatMessage(message_template, strs)
        else:
            sys.stderr.write("WARNING: Missing message"\
                            +" template for event record #%d.  (service: %s)\n"
                             % (msg_num, source))

        event_type_str = eventTypeEnum.get(event_type, None)
        if not event_type_str:
            event_type_str = "Unknown(0x%.4X)" % event_type

        # Format fields and return
        return {'msg_num':msg_num,
                'event_type':event_type_str,
                'date_created':time.strftime("%Y-%m-%d %H:%M:%S",
                                             time.gmtime(date_created)),
                'date_written':time.strftime("%Y-%m-%d %H:%M:%S",
                                             time.gmtime(date_written)),
                'source':source, 'category':category,
                'event_id':event_id, 'event_rva':"0x%s" % event_rva,
                'user':sid, 'computer':computer,
                'message':message,
                'strings':'|'.join(strs).strip('|'),
                'data':data}




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
        mdbs = self.svc_dbs["event"].get(service.lower().encode('ascii'), None)
        if mdbs:
            for mdb in mdbs.split(':'):
                ret_val = self.msg_dbs[mdb].get(rva, None)
                if ret_val:
                    # Templates shouldn't have any encoding issues.
                    # If they do, we want to know about them, since this
                    # means there's a bug in builddb.
                    ret_val = ret_val.decode(template_encoding)
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



# This is only here to aide in debugging.
# It will be overridden during a 'make install' below.
PATH_CONFIG='/usr/local/etc/grokevt'


################################################################################
### Below this line are build-time settings. ###
