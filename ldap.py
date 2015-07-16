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
            - Local path to an ldif file to modify the remote server;
              can be absolute or relative.
              If path is a directory, it is copied recursively.
        aliases: [ "src" ]
    destination:
        required: false
        default: "ldap://localhost"
        description:
             - URI of the server to be modified
        aliases: [ "dest","uri" ]
    bind_dn:
        required: false
        default: ""
        description:
             - DN with which to bind to the server.
               If empty, try an anonymous bind.
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
from os.path import isfile, expanduser
import base64

# == Class Definitions ====


class sourceFile(object):

    def __init__(self, module, l, filepath):
        self.module = module
        self.l = l
        self.changed = False
        self.entries = []
        self.source = filepath
        self.openFile = open(self.source)
        self.fileText = self.openFile.read()
        self.openFile.close()
        self.parse()

    def parse(self):
        # Normalize our newlines to unix
        self.fileText = self.fileText.replace('\r\n', '\n')
        self.fileText = self.fileText.replace('\r', '\n')
        # Replace newline space for sanity
        self.fileText = self.fileText.replace('\n ', '')
        # now split at the double new line
        self.splitFile = self.fileText.split('\n\n')
        for item in self.splitFile:
            if item == '':
                continue
            self.entries.append(entry(self.module, item, self.l))


class entry(object):
    def __init__(self, module, text, l):
        self.module = module
        self.l = l
        self.text = text
        self.dontchange = ['dn', 'changetype']
        self.dn = ''
        self.changeType = ''

        self.parse()
        self.changed = False

        if self.dn == '':
            self.module.fail_json(msg="Source file has an entry without a dn!")

    def go(self):

        if not self.changeType == '':
            if self.exists():

                if self.changeType == 'add':
                    self.module.fail_json(
                        msg="Cannot add entity dn=%s : it already exists."
                        % self.info['dn'])

                elif self.changeType == 'delete':
                    if not self.module.check_mode:
                        self.l.delete_s(self.dn)
                        self.changed = True

                elif self.changeType == 'modify':
                    attributesDone = []
                    self.changed = True
                    modlist = []

                    for delete in self.actions['delete']:
                        modlist.append((ldap.MOD_DELETE, delete, None))
                        attributesDone.append(delete)

                    for l in self.info:
                        if l[0] in attributesDone:
                            continue

                        if l[0] in self.dontchange:
                            continue

                        if l[0] in self.actions['add']:
                            modlist.append((ldap.MOD_ADD, l[0],
                                            self.changeList(l[0], l[1::])))
                            continue

                        changes = self.changeList(l[0], l[1::])

                        if len(changes) > 0:
                            modlist.append((ldap.MOD_REPLACE, l[0], l[1::]))

                    if len(modlist) > 0:
                        if not self.module.check_mode:
                            self.l.modify_s(self.dn, modlist)
                        self.changed = True

            else:
                if self.changeType == 'add':
                    modlist = []

                    for l in self.info:
                        if l[0] == 'changetype' or l[0] == 'dn':
                            continue

                        if not self.query[l[0]] == self.info[l[0]]:
                            modlist.append((l[0], l[1::]))

                    if len(modlist) > 0:
                        if not self.module.check_mode:
                            self.l.add_s(self.dn, modlist)
                        self.changed = True

                elif self.changeType == 'delete':
                    self.changed = False

                else:
                    self.module.fail_json(
                        msg="Tried to modify non-existant entity dn= %s"
                        % self.dn)
        else:
            if not self.exists():
                modlist = []

                for l in self.info:
                    if l[0] == 'changetype' or l[0] == 'dn':
                        continue

                    modlist.append((l[0], l[1::]))

                if not self.module.check_mode:
                    self.l.add_s(self.dn, modlist)

                self.changed = True

            else:
                attributesDone = []
                modlist = []

                for delete in self.actions['delete']:
                    modlist.append((ldap.MOD_DELETE, delete, None))
                    attributesDone.append(delete)

                for l in self.info:

                    if l[0] in self.dontchange:
                        continue

                    if l[0] in attributesDone:
                        continue

                    if l[0] in self.actions['add']:
                        modlist.append((ldap.MOD_ADD, l[0],
                                        self.changeList(l[0], l[1::])))
                        continue

                    changes = self.changeList(l[0], l[1::])

                    if l[0] not in self.query:
                        modlist.append((ldap.MOD_ADD, l[0], l[1::]))
                        continue

                    if len(changes) > 0:
                        modlist.append((ldap.MOD_REPLACE, l[0], l[1::]))

                if len(modlist) > 0:
                    if not self.module.check_mode:
                        self.l.modify_s(self.dn, modlist)
                    self.changed = True

    def listIndex(self, key):
        for index in range(0, len(self.info)):
            if(self.info[index][0] == key):
                return index

        return -1

    def changeList(self, key, values):
        if(key not in self.query):
            return values
        changes = []
        for v in values:
            if v not in self.query[key]:
                changes.append(v)

        return changes

    def parse(self):
        self.info = []
        self.actions = {'add': [], 'delete': []}
        for line in self.text.splitlines():
            line = line.strip(' \t\n\r')

            if line.startswith('#'):
                continue

            if line == '-':
                continue

            values = line.split(':', 1)

            values[0] = values[0].lower()

            if values[1].startswith(":"):
                values[1] = values[1][1:]
                values[1] = values[1].strip(' ')
                values[1] = base64.b64decode(values[1])
            else:
                values[1] = values[1].strip(' ')

            if values[0] == 'add' or values[0] == 'delete':
                self.actions[values[0]].append(values[1])
                continue

            if values[0] == 'dn':
                if self.dn == '':
                    self.dn = values[1]
                else:
                    module.fail_json(msg='Entry with more than one dn')
                continue

            if values[0] == 'changeType':
                self.changeType = values[1]
                continue

            if self.listIndex(values[0]) == -1:
                self.info.append([values[0], values[1]])

            else:
                self.info[self.listIndex(values[0])].append(values[1])

        self.dontchange.append(self.dn.split('=', 1)[0])

    def exists(self):
        # Parse the dn

        dn = self.dn
        Lfilter = '(objectclass=*)'
        attrs = ['*']
        try:
            self.query = self.l.search_s(dn, ldap.SCOPE_BASE,
                                         Lfilter, attrs)

            q = {}
            for key in self.query[0][1]:
                q[key.lower()] = [s for s in self.query[0][1][key]]
            self.query = q

        except ldap.NO_SUCH_OBJECT:
            return False
        return True

# =========================


def EntityKey(e):
    return e.info['dn'][0][::-1]


def main():

    module = AnsibleModule(
        argument_spec=dict(
            source=dict(required=True, aliases=['src'], type='str'),
            destination=dict(required=False, default='ldap://localhost',
                             aliases=['dest', 'uri']),
            bind_dn=dict(default='', aliases=['user']),
            bind_passwd=dict(default='', aliases=['pass', 'password']),
            ),
        supports_check_mode=True
        )

    result = {}

    result['source'] = module.params['source']
    result['destination'] = module.params['destination']
    result['bind_dn'] = module.params['bind_dn']
    result['bind_passwd'] = 'NOT_LOGGING_PASSWORD'

    l = ldap.initialize(module.params['destination'])
    username = module.params['bind_dn']
    password = module.params['bind_passwd']

    if not module.params['bind_dn'] == '':
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

    source = expanduser(module.params['source'])

    if isfile(source):

        try:
            src = sourceFile(module, l, source)
            entities = src.entries
            changed = False
            # entities.sort( key= EntityKey )

            for e in entities:
                e.go()

                if e.changed:
                    changed = True

            module.exit_json(changed=changed)

        except ldap.LDAPError, e:
            err = "LDAP ERROR : %s" % e
            module.fail_json(msg=err)

    l.unbind()
# import stuff required by ansible

from ansible.module_utils.basic import *
main()
