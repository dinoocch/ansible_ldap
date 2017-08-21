#!/usr/bin/python
# -*- coding: utf-8 -*-

# (c) 2016, Dino Occhialini
# Author : Dino Occhialini <dino.occhialini@gmail.com>

# Portions of this rewritten module have been inspired by the ldap_entry
#   module, a part of Ansible.

ANSIBLE_METADATA = {'status': ['preview'],
                    'supported_by': 'community',
                    'version': '1.0'}

DOCUMENTATION = '''
---
module: ldap_template
author: "Dino Occhialini"
short_description: Manage LDAP with LDIFF jinja templates
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
    base64_passwd:
        required: false
        default: ""
        description:
             - Base64 Encoded password
'''

EXAMPLES = '''
# Use file ldiff to connect to LDAPSERVER with anonymous bind
- ldap_template: src=ldiff dest="ldap://LDAPSERVER"
'''

from ansible.module_utils.basic import AnsibleModule # noqa

# Try importing ldap, if not fail so we can show an error
try:
    import ldap # noqa
    import ldap.modlist # noqa
    import ldap.sasl # noqa
    HAS_LDAP = True
except ImportError:
    HAS_LDAP = False

import base64 # noqa


# == Class Definitions ====
class LdapAttr:
    """
    Class for a single LDAP Attribute

    :attr state: State of the attribute (add, delete, exact)
    :attr attrs: Values that should be in Attribute
    """
    def __init__(self, state="add"):
        """
        Initialization function

        :param state: State for the attribute, Default add
        """
        self.state = state
        self.attrs = []

    def add(self, element):
        """
        Add a value to the list of values in attribute

        :param element: Element to add
        """
        self.attrs.append(element)


class LdapEntry:
    """
    Class representing LDAP Entry

    :param contents: Raw text of ldap entry
    :param attrs: Dictionary mapping attr to attr entity
    :param dn: Distinguished name of the entity
    :param changetype: Changetype for the entity
    """
    def __init__(self, contents):
        """
        Initialization for ldap entry

        :param contents: Content (text) for entry
        """
        self.contents = contents
        self.attrs = {}
        self.dn = None
        self.changetype = "modify"
        self.parse()

    def parse(self):
        """
        Function to parse an ldap entry
        """
        contents = self.contents
        for i in contents:
            data = i.split(':', 1)
            prop = data[0].lower().strip()
            attr = data[1].strip()

            if prop == "dn":
                self.dn = attr.strip()
            elif prop == "changetype":
                self.changetype = attr.strip().lower()
            elif prop in ("add", "delete", "exact"):
                if attr in self.attrs:
                    self.attrs[attr.lower()].state = prop
                else:
                    self.attrs[attr.lower()] = LdapAttr(state=prop)
            else:
                if prop not in self.attrs:
                    self.attrs[prop] = LdapAttr()
                if attr[0] == ":":
                    attr = attr[1:].strip()
                    attr = base64.b64decode(attr).strip()
                self.attrs[prop].add(attr)


class LdapConfig:
    """
    Class representing "entire" LDAP Configuration

    :attr contents: Raw contents for entries
    :attr host: Host to connect to
    :attr bind_dn: Dn to bind with
    :attr bind_pw: Password to bind using
    :attr start_tls: Use start_tls when connecting
    :attr module: Ansible module to use
    :attr changed: Boolean to show if config was changed
    :attr modified: List of modified entities
    """
    def __init__(self, contents=None, host=None, bind_dn=None, bind_pw=None,
                 start_tls=False, module=None):
        self.contents = contents
        self.host = host
        self.bind_dn = bind_dn
        self.bind_pw = bind_pw
        self.start_tls = start_tls
        self.module = module

        self.changed = False
        self.modified = []

    def parse(self):
        """
        Parse ldiff based on spec
        """
        entries = []
        current_entry = []
        previous_comment = False
        for line in self.contents.splitlines():
            if line == "":
                if len(current_entry) > 0:
                    entries.append(LdapEntry(current_entry))
                current_entry = []
                previous_comment = False
            elif line[0] == " ":
                # Lines starting with a comma are continuations from previous
                if not previous_comment:
                    current_entry[-1] = "{0} {1}".format(current_entry[-1],
                                                         line.strip())
                else:
                    continue
            elif line.lstrip()[0] == "#":
                # # indicates a comment
                previous_comment = True
                continue
            elif line.strip() == "-":
                # ldap cares, we don't
                continue
            else:
                current_entry.append(line.strip())
                previous_comment = False
        self.entries = entries

    def find(self, dn, attrs=None):
        """
        Find

        :param attrs:  Specific list of attributes to look for
        """
        if attrs is None:
            attrs = ["*"]
        filter = '(objectclass=*)'  # everything has an objectclass
        try:
            q = self.connection.search_s(dn, ldap.SCOPE_BASE,
                                         filter, attrs)
        except ldap.NO_SUCH_OBJECT:
            return None
        except ldap.LDAPError as exc:
            self.module.fail_json(msg="Failed to query ldap.",
                                  detail=exc.message)

        query = {}
        for key in q[0][1]:
            query[key.lower()] = [s for s in q[0][1][key]]
        return query

    def add(self, entry):
        """
        Add an entry to ldap

        MODIFIES CONFIG

        :param entry: Entry to add
        """
        d = dict((key, value.attrs) for (key, value) in entry.attrs.items())
        modlist = ldap.modlist.addModlist(d)
        try:
            self.connection.add_s(entry.dn, modlist)
        except ldap.LDAPError as exc:
            self.module.fail_json(msg="Failed to add dn {0}".format(entry.dn),
                                  details=exc.message)

    def delete(self, entry):
        """
        DELETES an entry from ldap

        MODIFIES CONFIG

        :param entry: Entry to delete
        """
        try:
            self.connection.delete_s(entry.dn)
        except ldap.LDAPError as exc:
            self.module.fail_json(msg="Failed to delete {0}".format(entry.dn),
                                  details=exc.message)

    def diff(self, entry, existing):
        """ Diff two entries """
        modlist = []
        for attr in entry.attrs:
            if attr in existing:
                current = set(existing[attr])
            else:
                current = set([])
            todo = set(entry.attrs[attr].attrs)
            if entry.attrs[attr].state == "add":
                changes = todo - current
                if len(changes) == 0:
                    continue
                modlist.append((ldap.MOD_ADD, attr, list(changes)))
            elif entry.attrs[attr].state == "delete":
                if len(current) == 0:
                    continue
                modlist.append((ldap.MOD_DELETE, attr, None))
            elif entry.attrs[attr].state == "exact":
                adds = todo - current
                deletes = current - todo
                if len(adds) > 0:
                    modlist.append((ldap.MOD_ADD, attr, list(adds)))
                if len(deletes) > 0:
                    modlist.append((ldap.MOD_DELETE, attr, list(deletes)))
        return modlist

    def mod(self, entry, existing, exact=False, check=False):
        """ This function modifies ldap entries """
        modlist = self.diff(entry, existing)
        if exact:
            for attr in existing:
                if attr not in entry.attrs:
                    modlist.append((ldap.MOD_DELETE, attr, None))

        if len(modlist) == 0:
            return
        self.modified.append(entry.dn)
        self.changed = True
        if check:
            return

        try:
            self.connection.modify_s(entry.dn, modlist)
        except ldap.LDAPError as exc:
            self.module.fail_json(msg="Failed modify {0}".format(entry.dn),
                                  details=exc.message)

    def modify(self, check=False):
        """
        Modify (with check mode)

        :param check: Check mode
        """
        for entry in self.entries:
            existing = self.find(entry.dn, attrs=entry.attrs.keys())
            if existing is None:
                if entry.changetype == "delete":
                    # no change
                    continue
                if "objectclass" not in entry.attrs:
                    self.module.fail_json(msg="Entries must have objectclass")

                self.changed = True
                self.modified.append(entry.dn)

                if not check:
                    self.add(entry)
                continue

            if entry.changetype == "delete":
                self.changed = True
                self.modified.append(entry.dn)

                if not check:
                    self.delete(entry)

            elif entry.changetype == "add":
                continue

            elif entry.changetype == "modify":
                self.mod(entry, existing, exact=False, check=check)

            elif entry.changetype == "exact":
                self.mod(entry, existing, exact=True, check=check)

    def connect(self):
        """
        Connect to ldap
        """
        connection = ldap.initialize(self.host)

        if self.start_tls:
            try:
                connection.start_tls_s()
            except ldap.LDAPError as exc:
                self.module.fail_json(msg="Cannot start tls.",
                                      details=exc.message)

        try:
            if self.bind_dn is None:
                connection.sasl_interactive_bind_s('', ldap.sasl.external())
            else:
                connection.simple_bind_s(self.bind_dn, self.bind_pw)
        except ldap.INVALID_CREDENTIALS as exc:
            self.module.fail_json(msg="Invalid credentials.",
                                  details=exc.message)
        except ldap.LDAPError as exc:
            self.module.fail_json(msg="Cannot bind to server.",
                                  details=exc.message)

        self.connection = connection


def main():
    argument_spec = dict(
        src=dict(required=True, no_log=True),
        destination=dict(default='ldap://'),
        bind_dn=dict(default=None),
        bind_passwd=dict(default=None, no_log=True),
        base64_passwd=dict(default=False, type='bool'),
        start_tls=dict(default=False, type='bool')
    )

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True)

    if not HAS_LDAP:
        module.fail_json(msg="Missing required 'python-ldap' module.")

    if module.params['base64_passwd']:
        bind_pw = base64.b64decode(module.params['bind_passwd'])
    else:
        bind_pw = module.params['bind_passwd']

    ldap_config = LdapConfig(contents=module.params['src'],
                             host=module.params['destination'],
                             bind_dn=module.params['bind_dn'],
                             bind_pw=bind_pw,
                             start_tls=module.params['start_tls'],
                             module=module
                             )

    ldap_config.parse()
    ldap_config.connect()

    ldap_config.modify(check=module.check_mode)

    module.exit_json(changed=ldap_config.changed,
                     modified=ldap_config.modified
                     )


main()
