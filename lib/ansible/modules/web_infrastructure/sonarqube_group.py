#!/usr/bin/python
# -*- coding: utf-8 -*-

# Ansible module to manage Sonarqube user groups
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
module: sonarqube_user_group

short_description: Manage Sonarqube user groups.
description:
    - Create and remove Sonarqube groups through HTTP API.
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
    description:
        description:
            - Sets the group description.
        required: False
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
- name: Create a Sonarqube group
  sonarqube_group:
    name: "lala"
    description: "my new lala group"
    url: "https://sonarqube.example.org"
    user: "myuser"
    password: "mypassword"
    state: present

- name: Create a Sonarqube group via token
  sonarqube_group:
    name: "lala"
    description: "my new lala group"
    url: "https://sonarqube.example.org"
    user: "myToken"
    state: present

- name: Remove a Sonarqube group
  sonarqube_group:
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
    description: dictionnary containing project informations before modification
    returned: success
    type: dict
after:
    description: dictionnary containing project informations after modification
    returned: success
    type: dict
'''

# import module snippets
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.six.moves.urllib.parse import urlencode
from ansible.module_utils._text import to_native
from ansible.module_utils.urls import fetch_url
import json


class SonarqubeGroupManager(object):
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

    def request_sonarqube_api(self, api_path, data, method="GET"):
        resp, info = fetch_url(self.module,
                               "%s/api/user_groups/%s" % (self.module.params["url"], api_path),
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

    def get_group(self):
        resp, info = self.request_sonarqube_api("search", {"name": self.module.params["name"]})
        result = list(
            filter(lambda group: group['name'] == self.module.params["name"], resp['groups'])
        )

        if len(result) > 0:
            return result[0]

        return None

    def create_or_update_group(self):
        facts = self.get_group()
        if facts is None:
            # If in check mode don't create group, simulate a fake group creation
            if self.module.check_mode:
                self.module.exit_json(changed=True, before={}, after={"name": self.module.params["name"]})

            resp, info = self.request_sonarqube_api("create", method="POST", data={
                "name": self.module.params["name"],
                "description": self.module.params["description"],
            })

            if info["status"] == 200:
                self.module.exit_json(changed=True, before={}, after=self.get_group())
            else:
                self.module.fail_json(msg="Unhandled HTTP status %d, please report the bug" % info["status"],
                                      before={}, after=self.get_group())
        else:
            self.module.exit_json(changed=False, before=facts, after=facts)

    def remove_group(self):
        facts = self.get_group()
        if facts is None:
            self.module.exit_json(changed=False, before={}, after={})
        else:
            # If not in check mode, remove the group
            if not self.module.check_mode:
                self.request_sonarqube_api("delete", method="POST", data={
                    "name": self.module.params["name"],
                })
            self.module.exit_json(changed=True, before=facts, after={})


def main():
    module = AnsibleModule(
        argument_spec=dict(
            state=dict(type='str', choices=['present', 'absent'], default='present'),
            name=dict(required=True, type='str'),
            description=dict(required=False, type='str'),
            url=dict(type='str', default='http://localhost:9000'),
            user=dict(required=True, type='str', no_log=True),
            password=dict(type='str', no_log=True, default=''),
        ),
        supports_check_mode=True
    )

    module.params['url_username'] = module.params['user']
    module.params['url_password'] = module.params['password']
    module.params['force_basic_auth'] = True

    sonarqube = SonarqubeGroupManager(module)
    if module.params['state'] == 'present':
        sonarqube.create_or_update_group()
    elif module.params['state'] == 'absent':
        sonarqube.remove_group()


if __name__ == '__main__':
    main()
