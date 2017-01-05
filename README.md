#Ansible LDAP Module
Just another Ansible module.  Designed for interfacing with an LDAP server to
apply an LDIF file (or many such files)

## Options
```yml
---
host:
    required: false
    type: string
    default: "ldap://localhost"
    description: "URI of ldap server"

bind_dn:
    required: false
    type: string
    default: ""
    description:
        - DN to bind to the server.
        - If empty, try an anonymous bind.

bind_passwd:
    required: false
    type: string
    default: ""
    description:
        - password to use with bind_dn

base64_passwd:
    required: false
    type: boolean
    default: false
    description:
        - Base64 Encoded Password
        - Convenience function for if you base64 encode your passwords
        - Helps with Jinja oddities

source_file:
    required: false
    type: string
    description: Path to an ldif file or directory
    aliases: "src"
```

# Additions to LDAP specification
changetype (comparable to ansible state):
  * `add` - add the ldap entry, if it already exists don't modify it
  * `modify` - add the ldap entry if it doesn't exist, add all attributes not present (default)
  * `delete` - delete the ldap entry if it exists
  * `exact` - Enforce all attributes

attribute modifiers:
  * `add` - add all attributes not present (default)
  * `delete` - delete the attribute
  * `exact` - Enforce desired attributes (only)
