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
