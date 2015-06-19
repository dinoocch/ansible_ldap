#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2015, Collegium V collegiumv.org
# Author : Dino Occhialini <dino.occhialini@gmail.com>

DOCUMENTATION = '''
---
module: ldap
author: "Dino Occhialini"
short_description: Manage LDAP with LDIFF
requirements: [ python-ldap ]
description:
    - Manage LDAP using an LDIFF configuration file
options:
    source:
        required: true
        description:
            - Local path to an ldif file to modify the remote server; can be absolute or relative. If path is a directory, it is copied recursively.
        aliases: [ "src" ]
    destination:
        required: false
        default: "ldap://localhost:1390"
        description:
             - URI of the server to be modified
        aliases: [ "dest","uri" ]
    bind_dn:
        required: false
        default: ""
        description:
             - DN with which to bind to the server. If empty, try an anonymous bind.
        alias: [ "user" ]
    bind_passwd:
        required: false
        default: ""
        description:
             - Password to use with bind_dn
'''

EXAMPLES = '''
# Use file ldiff to connect to LDAPSERVER with anonymous bind
- ldap: src=ldiff dest="ldap://LDAPSERVER"

# Use file ldiff to connect to LDAPSERVER with bind user and pass
- ldap: src=ldiff dest="ldap://LDAPSERVER" bind_dn="user" bind_passwd="pass"

'''

import ldap
import os
import sys
import re

# == Class Definitions ====

class sourceFile(object):

    def __init__(self, module, l,filepath):
        self.module = module
        self.l = l
        self.changed = False
        self.entries = []
        self.source = filepath
        self.openFile = open(self.source)
        self.fileText = openFile.read()
        self.openFile.close()
        self.parse()

    def parse(self):
        # Normalize our newlines to unix
        self.fileText = self.fileText.replace('\r\n','\n')
        self.fileText = self.fileText.replace('\r','\r')
        # Replace newline space for sanity
        self.fileText = self.fileText.replace('\n ', '')
        #now split at the double new line
        self.splitFile = self.fileText.split('\n\n')
        for item in splitFile:
            if item == '':
                continue
            self.entries.append(Entry(module,item,l))

    def go(self):
        for entry in self.entries:
            entry.go()
            if entry.changed:
                self.changed = True

class entry(object):
    def __init__(self, module, text,l):
        self.module = module
        self.l = l
        self.text = text
        self.parse()
        self.changed = False
        if 'dn' not in self.info:
            self.module.fail_json(msg="Source file has an entry without a dn!")

    def go(self):
        if 'changetype' in self.info:

            if self.exists():
                if self.info['changetype'] == 'add':
                    self.module.fail_json(msg="Cannot add entity dn=%s : it already exists." % self.info['dn'])
                elif self.info['changetype'] == 'delete':
                    if not self.module.check_mode:
                        l.delete_s(self.info['dn'])
                        self.changed = True
                elif self.info['changetype'] == 'modify':
                    attributesDone = []
                    self.changed = True
                    modlist = []
                    for add in actions['add']:
                        modlist.append( (ldap.MOD_ADD,add,self.info[add]) )
                        attributesDone.append(add)
                    for delete in actions['delete']:
                        modlist.append( (ldap.MOD_DELETE,delete,None) )
                        attributesDone.append(delete)
                    for key in self.info:
                        if key == 'dn' or key == 'changetype':
                            continue
                        if key in attributesDone:
                            continue
                        modlist.append( (ldap.MOD_REPLACE, key, self.info[key]) )

                    if not self.module.check_mode:
                        l.modify_s(self.info['dn'],modlist)


            else:
                if self.info['changetype'] == 'add':
                    if not self.module.check_mode:
                        modlist = []
                        for key in self.info:
                            if key == 'dn' or key == 'changetype':
                                continue
                            modlist.append( ( key, self.info[key] ) )
                        l.add(self.info['dn'],modlist)
                    self.changed = True
                elif self.info['changetype'] == 'delete':
                    self.changed = False
                else:
                    self.module.fail_json(msg="Tried to modify non-existant entity dn= %s" % self.info['dn'])
        else:
            if not self.exists():
                modlist = []
                for key in self.info:
                    if key == 'dn' or key == 'changetype':
                        continue
                    modlist.append( ( key, self.info[key] ) )
                if not self.module.check_mode:
                    l.add( self.info['dn'], modlist)
                self.changed = True
            else:
                attributesDone = []
                modlist = []
                for add in actions['add']:
                    modlist.append( (ldap.MOD_ADD,add,self.info[add]) )
                    attributesDone.append(add)
                for delete in actions['delete']:
                    modlist.append( (ldap.MOD_DELETE,delete,None) )
                    attributesDone.append(delete)
                for key in self.info:
                    if key == 'dn' or key == 'changetype':
                        continue
                    if key in attributesDone:
                        continue
                    modlist.append( (ldap.MOD_REPLACE, key, self.info[key]) )
                if not self.module.check_mode:
                    l.modify(self.info['dn'],modlist)
                self.changed = True

    def parse(self):
        self.info = {}
        self.actions = {'add':[],'delete':[]}
        for line in self.text.splitlines():
            line = line.strip(' \t\n\r')
            if line.startswith('#'):
               continue

           if line == '-':
               continue
               
            p = re.compile('\s*:\s*')
            values = p.split(text,1)
            if values[0] == 'add' or values[0] == 'delete':
                actions[values[0]].append(values[1])
                continue
            if values[0] not in self.info):
                self.info[values[0]] = [values[1]]
            else:
                self.info[values[0]].append(values[1])

    def exists(self):
        # Parse the dn

        dn = self.info['dn']
        filter = '(objectclass=*)'
        attrs = ['*']
        try:
            self.query = l.search_s(dn,ldap.SCOPE_BASE,filter)
        except ldap.NO_SUCH_ATTRIBUTE:
            return False
        return True
# =========================

def main():
    module = AnsibleModule(
        argument_spec = dict(
            source=dict(required=True, aliases=['src'], type='str'),
            destination=dict(default='ldap://localhost:1390', aliases=['dest','uri']),
            bind_dn=dict(default='', aliases=['user']),
            bind_passwd=dict(default='', aliases=['pass','password']),
            ),
        supports_check_mode=True
        )

    result = {}

    result['source'] = module.params['source']
    result['destination'] = module.params['destination']
    result['bind_dn'] = module.params['bind_dn']
    result['bind_passwd'] = 'NOT_LOGGING_PASSWORD'



    l = ldap.initialize(module.destination)
    username = module.params['bind_dn']
    password = module.params['bind_passwd']
    if not module.bind_dn == '':
        try:
            l.bind_s(username, password)
        except ldap.INVALID_CREDENTIALS:
            # result['msg'] = "Failed to bind. Invalid Credientials."
            # result['failed'] = True
            module.fail_json(msg="Failed to bind. Invalid Credentials.")
        except ldap.LDAPError, e:
            err = "LDAP ERROR : %s" % e
            # result['failed'] = True
            module.fail_json(msg=err)
    else:
        try:
            l.simple_bind_s()
        except ldap.LDAPError, e:
            err = "LDAP ERROR : %s" % e
            # result['failed'] = True
            module.fail_json(msg=err)

    source = os.path.expanduser(module.params['source'])
    if os.path.isfile(source):
        src = SourceFile(module,l,source)
        src.go()
        module.exit_json(changed=src.changed)

    elif os.path.isdir(source):
        sourceFiles = []
        for root, subdirs, files in os.walk(source):
            for filename in files:
                path = os.path.join(source,filename)
                sourceFiles.append(sourceFile(module,l,path))
        changed = False
        for src in sourceFiles:
            src.go()
            if src.changed:
                changed = True
        module.exit_json(changed=changed)

    else:
        module.fail_json(msg="Unable to locate file/directory.")
# import stuff required by ansible
from ansible.module_utils.basic import *
main()
