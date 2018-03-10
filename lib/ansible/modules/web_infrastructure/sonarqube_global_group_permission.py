#!/usr/bin/python
# -*- coding: utf-8 -*-

# Ansible module to manage Sonarqube global group permissions.
# (c) 2018, Johannes Graf <graf.johannes@gmail.com>
#
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)

from __future__ import absolute_import, division, print_function
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'community'}

DOCUMENTATION = '''
---
module: sonarqube_global_group_permission

short_description: Manage Sonarqube global group permissions.
description:
    - Grant and revoke permissions to make changes at the global level.
version_added: "2.4"
author: "Johannes Graf (@grafjo)"
options:
    state:
        description:
            - Create or remove Sonarqube group.
        choices: ['present', 'absent']
        default: 'present'
    name:
        description:
            - Sets the group name.
        required: True
    permissions:
        description:
            - Granted permissions for the given group
        choices: ["admin", "gateadmin", "profileadmin", "provisioning", "scan"]
    url:
        description:
            - Sets the Sonarqube instance URL.
        default: 'http://localhost:9000'
        required: True
    user:
        description:
            - Sets Sonarqube API user
            - Sonarqube API token can be used here, too. In this case, don't provide a password!
        required: True
    password:
        description:
            - Sets Sonarqube API password of the given user.
        required: false
'''

EXAMPLES = '''
- name: Add full global permissions to Sonarqube group lala
  sonarqube_global_group_permission:
    name: "lala"
    permissions:
        - "admin"
        - "gateadmin"
        - "profileadmin"
        - "provisioning"
        - "scan"
    url: "https://sonarqube.example.org"
    user: "myuser"
    password: "mypassword"
    state: present

- name: Add full global permissions to Sonarqube group lala via token
  sonarqube_global_group_permission:
    name: "lala"
    permissons:
        - "admin"
        - "gateadmin"
        - "profileadmin"
        - "provisioning"
        - "scan"
    url: "https://sonarqube.example.org"
    user: "myToken"
    state: present

- name: Remove all global permissions from Sonarqube group lala
  sonarqube_global_group_permission:
    name: "lala"
    url: "https://sonarqube.example.org"
    user: "myuser"
    password: "mypassword"
    state: absent
'''

RETURN = '''
sonarqube_response:
    description: Sonarqube response when a failure occurs
    returned: failed
    type: string
before:
    description: dictionnary containing global group permission informations before modification
    returned: success
    type: dict
after:
    description: dictionnary containing global group permission informations after modification
    returned: success
    type: dict
'''

# import module snippets
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.six.moves.urllib.parse import urlencode
from ansible.module_utils._text import to_native
from ansible.module_utils.urls import fetch_url
import json


class SonarqubeGlobalGroupPermissionManager(object):
    def __init__(self, module):
        self.module = module

    def handle_http_code_if_needed(self, infos):
        if infos["status"] == 401:
            self.module.fail_json(msg="Unauthorized - check your provided credentials!")
        if infos["status"] == 403:
            self.module.fail_json(msg="Token not allowed. Please ensure token is allowed or has the correct "
                                      "permissions.", sonarqube_response=infos["body"])
        elif infos["status"] >= 500:
            self.module.fail_json(msg="Fatal Sonarqube API error.", sonarqube_response=infos["body"])

    def request_sonarqube_api(self, api_path, data={}, method="GET"):
        resp, info = fetch_url(self.module,
                               "%s/api/permissions/%s" % (self.module.params["url"], api_path),
                               data=urlencode(data),
                               method=method,
                               headers={
                                   "Content-Type": "application/x-www-form-urlencoded",
                                   "Accept": "application/json",
                               })

        self.handle_http_code_if_needed(info)

        if info["status"] == 204:
            return resp, info

        if resp is not None:
            resp = resp.read()
            if resp != "":
                try:
                    json_resp = json.loads(resp)
                    return json_resp, info
                except ValueError as e:
                    self.module.fail_json(msg="Sonarqube response was not a valid JSON. Exception was: %s. "
                                              "Object was: %s" % (to_native(e), resp))
        return resp, info

    def get_permissons_of_group(self):
        resp, info = self.request_sonarqube_api("groups")
        result = list(
            filter(lambda group: group['name'] == self.module.params["name"], resp['groups'])
        )

        if len(result) > 0:
            return result[0]

        return None

    def create_or_update_global_group_permissions(self):
        facts = self.get_permissons_of_group()
        if facts is None:
            self.create_permissions()
        else:
            self.update_permissions(facts)

    def remove_global_group_permissions(self):
        facts = self.get_permissons_of_group()
        if facts is None:
            self.module.exit_json(changed=False, before={}, after={})
        else:
            # If not in check mode, remove all global permissions of the given group
            if not self.module.check_mode:
                self.remove_given_permissions(given_permissions=facts['permissions'])

            self.module.exit_json(changed=True, before=facts, after={})

    def update_permissions(self, facts):
        # check if all required permission are set
        given_permissions = facts["permissions"]
        expected_permissions = self.module.params["permissions"]

        permisions_to_add = set(expected_permissions).difference(given_permissions)
        permisions_to_remove = set(given_permissions).difference(expected_permissions)

        if len(permisions_to_add) == 0 and len(permisions_to_remove) == 0:
            # no changes so we can exit here
            self.module.exit_json(changed=False, before=facts, after=facts)

        self.add_given_permissions(permisions_to_add)
        self.remove_given_permissions(given_permissions=permisions_to_remove)

        self.module.exit_json(changed=True, before=facts, after=self.get_permissons_of_group())

    def create_permissions(self):
        # If in check mode don't create group, simulate a fake group creation
        if self.module.check_mode:
            self.module.exit_json(changed=True, before={}, after={"name": self.module.params["name"], "permissions": self.module.params["permissions"]})

        self.add_given_permissions(permisions_to_add=self.module.params['permissions'])

        new_facts = self.get_permissons_of_group()
        if new_facts is None:
            self.module.fail_json(msg="Something went wrong adding permissions to name=%s" % self.module.params["name"], before={}, after={})
        else:
            self.module.exit_json(changed=True, before={}, after=new_facts)

    def remove_given_permissions(self, given_permissions):
        for permission in given_permissions:
            self.request_sonarqube_api("remove_group", method="POST", data={
                "groupName": self.module.params["name"],
                "permission": permission,
            })

    def add_given_permissions(self, permisions_to_add):
        for permission in permisions_to_add:
            self.request_sonarqube_api("add_group", method="POST", data={
                "groupName": self.module.params["name"],
                "permission": permission,
            })


def main():
    module = AnsibleModule(
        argument_spec=dict(
            state=dict(type='str', choices=['present', 'absent'], default='present'),
            name=dict(required=True, type='str'),
            permissions=dict(required=False, type='list'),
            url=dict(type='str', default='http://localhost:9000'),
            user=dict(required=True, type='str', no_log=True),
            password=dict(type='str', no_log=True, default=''),
        ),
        supports_check_mode=True
    )

    module.params['url_username'] = module.params['user']
    module.params['url_password'] = module.params['password']
    module.params['force_basic_auth'] = True
    module.tmpdir = '/tmp'

    sonarqube = SonarqubeGlobalGroupPermissionManager(module)
    if module.params['state'] == 'present':
        sonarqube.create_or_update_global_group_permissions()
    elif module.params['state'] == 'absent':
        sonarqube.remove_global_group_permissions()


if __name__ == '__main__':
    main()
