#!/usr/bin/python
# -*- coding: utf-8 -*-

# Ansible module to manage Sonarqube a permission template
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
module: sonarqube_permission_template

short_description: Manage Sonarqube a permission template.
description:
    - Create, manage and remove a permission template through Sonarqube HTTP API.
version_added: "2.4"
author: "Johannes Graf (@grafjo)"
options:
    state:
        description:
            - Create or remove Sonarqube permission template.
        choices: ['present', 'absent']
        default: 'present'
    name:
        description:
            - Sets the permission template name.
        required: True
    description:
        description:
            - Sets the permisson template description.
        required: False
    project_key_pattern:
        description:
            - Sets the project key pattern. Must be a valid Java regular expression e.g. .*\.finance\..*
        default: ''
    group_permissions:
        description:
            - Sets the permission of given groups.
        required: False
    project_creator_permissions:
        description:
            - When a new project is created, the user who creates the project will receive this permission on the project.
        required: False
    default_template:
        description:
        - Set this permission template as default.
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
- name: Create a Sonarqube permission template
  sonarqube_permission_template:
    name: "lala"
    description: "my new lala permission template"
    group_permissions:
      - group_name: "lala_group"
        permissions: ['admin', 'codeviewer', 'issueadmin', 'scan', 'user']
      - group_name: "lulu_group"
        permissions: ['scan']
    create_project_permissons: ['codeviewer', 'issueadmin', 'scan', 'user']
    url: "https://sonarqube.example.org"
    user: "myuser"
    password: "mypassword"
    state: present

- name: Create a Sonarqube permission template via token
  sonarqube_permission_template:
    name: "lala"
    description: "my new lala permission template"
    url: "https://sonarqube.example.org"
    user: "myToken"
    state: present

- name: Remove a Sonarqube permission template
  sonarqube_permission_template:
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
    description: dictionnary containing permission template informations before modification
    returned: success
    type: dict
after:
    description: dictionnary containing permission template informations after modification
    returned: success
    type: dict
'''

# import module snippets
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.six.moves.urllib.parse import urlencode
from ansible.module_utils._text import to_native
from ansible.module_utils.urls import fetch_url
import json


class SonarqubePermissionTemplateManager(object):
    def __init__(self, module):
        self.module = module
        self.currentState = {}
        self.targetState = {}
        self.changed = False

    def handle_http_code_if_needed(self, infos):
        if infos["status"] == 401:
            self.module.fail_json(msg="Unauthorized - check your provided credentials!")
        if infos["status"] == 403:
            self.module.fail_json(msg="Token not allowed. Please ensure token is allowed or has the correct "
                                      "permissions.", sonarqube_response=infos["body"])
        elif infos["status"] >= 500:
            self.module.fail_json(msg="Fatal Sonarqube API error.", sonarqube_response=infos["body"])

    def request_sonarqube_api(self, api_path, data={}, method="GET"):
        print("data=%s" % data)
        url = "%s/api/permissions/%s" % (self.module.params["url"], api_path)
        print("url=%s" % url)
        resp, info = fetch_url(self.module,
                               url,
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

    def get_permission_template(self):
        resp, info = self.api_permissions_search_templates(self.module.params["name"])
        return self.filter_permission_template(response=resp)

    def filter_permission_template(self, response):
        if response is not None:
            print("permissionTemplates=%s" % response["permissionTemplates"])
            result = list(
                filter(lambda permission_template: permission_template['name'] == self.module.params["name"], response['permissionTemplates'])
            )

            if len(result) > 0:
                return result[0]

        return None

    def create_or_update_permission_template(self):
        facts = self.get_permission_template()
        if facts is None:
            print("create_permission_template")
            self.create_permission_template()
        else:
            print("update_permission_template")
            self.update_permission_template(facts)

    def update_permission_template(self, facts):
        print("checking permissions")
        self.maintain_group_permissions()
        self.maintain_project_creator_permissions(facts)
        self.maintain_default_template()

        self.maintain_permission_template(facts)

        self.module.exit_json(changed=self.changed, before=self.currentState, after=self.targetState)

    def maintain_group_permissions(self):
        current_group_permissions = self.get_template_groups()
        expected_group_permissions = self.module.params["group_permissions"]

        self.currentState["group_permissions"] = list(({"name": x["name"], "permissions": x["permissions"]})for x in current_group_permissions)
        self.targetState["group_permissions"] = expected_group_permissions

        current_group_names = set((x["name"]) for x in current_group_permissions)
        expected_group_names = set((x["group_name"]) for x in expected_group_permissions)

        print("current_group_names=%s" % current_group_names)
        print("expected_group_names=%s" % expected_group_names)

        self.add_group_permissions_to_template(current_group_names, expected_group_names, expected_group_permissions)
        self.remove_group_permissions_from_template(current_group_names, current_group_permissions, expected_group_names)
        self.update_existing_group_permissions_of_template(current_group_names, current_group_permissions, expected_group_names,
                                                           expected_group_permissions)

    def maintain_project_creator_permissions(self, facts):
        current_project_creator_permissions = sorted(set((x["key"]) for x in list(
            filter(lambda group_permission: group_permission["withProjectCreator"] == True, facts["permissions"])
        )))
        expected_project_creator_permissions = sorted(self.module.params["project_creator_permissions"])

        print("current_project_creator_permissions=%s" % current_project_creator_permissions)
        print("expected_project_creator_permissions=%s" % expected_project_creator_permissions)

        self.currentState["project_creator_permissions"] = current_project_creator_permissions
        self.targetState["project_creator_permissions"] = expected_project_creator_permissions

        project_creator_permissions_to_add = set(expected_project_creator_permissions).difference(current_project_creator_permissions)
        project_creator_permissions_to_remove = set(current_project_creator_permissions).difference(expected_project_creator_permissions)

        if len(project_creator_permissions_to_add) > 0 or len(project_creator_permissions_to_remove) > 0:
            self.changed = True

        print("project_creator_permissions_to_add=%s" % project_creator_permissions_to_add)
        print("project_creator_permissions_to_remove=%s" % project_creator_permissions_to_remove)

        template_name = self.module.params["name"]

        for project_creator_permission in project_creator_permissions_to_add:
            self.api_permissions_add_project_creator_to_template(
                template_name=template_name,
                permission=project_creator_permission
            )

        for project_creator_permission in project_creator_permissions_to_remove:
            self.api_permissions_remove_project_creator_from_template(
                template_name=template_name,
                permission=project_creator_permission
            )

    def maintain_default_template(self):
        resp, info = self.api_permissions_search_templates(self.module.params["name"])
        permission_template = self.filter_permission_template(response=resp)

        if (permission_template is not None):
            default_templates = resp["defaultTemplates"]
            if (len(default_templates) > 0):
                current_default_template = default_templates[0]
                if (current_default_template["templateId"] != permission_template["id"]):
                    self.currentState["default_template"] = False
                    self.targetState["default_template"] = True
                    self.changed = True
                    print("current defaultPermissionTemplate=%s" % current_default_template)
                    self.api_permissions_set_default_template(self.module.params["name"])

    def maintain_permission_template(self, facts):
        template_name = self.module.params["name"]
        description = self.module.params["description"]
        project_key_pattern = self.module.params["project_key_pattern"]

        changed = False
        if facts["name"] != template_name:
            self.currentState["name"] = facts["name"]
            self.targetState["name"] = template_name
            changed = True

        if facts["description"] != description:
            self.currentState["description"] = facts["description"]
            self.targetState["description"] = description
            changed = True

        if facts["projectKeyPattern"] != project_key_pattern:
            self.currentState["project_key_pattern"] = facts["projectKeyPattern"]
            self.targetState["project_key_pattern"] = project_key_pattern
            changed = True

        template_id = facts["id"]

        if changed:
            self.changed = True
            return self.api_permissions_update_template(template_id, template_name, description, project_key_pattern)

    def update_existing_group_permissions_of_template(self, current_group_names, current_group_permissions, expected_group_names,
                                                      expected_group_permissions):
        # those groups exists - just align permissions
        print("updating existing groups to permission template")
        common_group_names = set(current_group_names).intersection(expected_group_names)
        for common_group_name in common_group_names:
            print("updating group group_name=%s" % common_group_name)
            current_group_permission = list(
                filter(lambda group_permission: group_permission["name"] == common_group_name, current_group_permissions)
            )[0]
            expected_group_permission = list(
                filter(lambda group_permission: group_permission["group_name"] == common_group_name, expected_group_permissions)
            )[0]

            template_name = self.module.params["name"]

            permissions_to_add = set(expected_group_permission["permissions"]).difference(current_group_permission["permissions"])
            if len(permissions_to_add) > 0:
                self.changed = True
                print("adding group_name=%s with new permissions=%s" % (common_group_name, permissions_to_add))
                for permission in permissions_to_add:
                    self.api_permissions_add_group_to_template(common_group_name, permission, template_name)
            else:
                print("group_name=%s has no permissions to add!" % common_group_name)

            permissions_to_remove = set(current_group_permission["permissions"]).difference(expected_group_permission["permissions"])
            if len(permissions_to_remove) > 0:
                self.changed = True
                print("removing group_name=%s permissions=%s" % (common_group_name, permissions_to_remove))
                for permission in permissions_to_remove:
                    self.api_permissions_remove_group_from_template(common_group_name, permission, template_name)
            else:
                print("group_name=%s has no permissions to remove" % common_group_name)

    def remove_group_permissions_from_template(self, current_group_names, current_group_permissions, expected_group_names):
        groups_to_remove = set(current_group_names).difference(expected_group_names)
        print("removing existing groups from permission template: %s" % groups_to_remove)

        if len(groups_to_remove) > 0:
            self.changed = True

        for group in groups_to_remove:
            group_with_permissions = list(
                filter(lambda group_permission: group_permission["name"] == group, current_group_permissions)
            )

            if len(group_with_permissions) == 1:
                print("removing permissions in group_name=%s" % group_with_permissions[0])
                for permission in group_with_permissions[0]["permissions"]:
                    self.api_permissions_remove_group_from_template(group_with_permissions[0]["name"], permission, self.module.params["name"])

    def add_group_permissions_to_template(self, current_group_names, expected_group_names, expected_group_permissions):
        groups_to_add = set(expected_group_names).difference(current_group_names)
        print("adding new groups to permission template: %s" % groups_to_add)
        if len(groups_to_add) > 0:
            self.changed = True

        for group in groups_to_add:
            group_with_permissions = list(
                filter(lambda group_permission: group_permission["group_name"] == group, expected_group_permissions)
            )

            if len(group_with_permissions) == 1:
                print("adding permissions to new group group_name=%s" % group_with_permissions[0])
                for permission in group_with_permissions:
                    self.api_permissions_add_group_to_template(group_with_permissions[0]["name"], permission, self.module.params["name"])

    def create_permission_template(self):
        # If in check mode don't create group, simulate a fake group creation
        name = self.module.params["name"]
        if self.module.check_mode:
            self.module.exit_json(changed=True, before={}, after=self.module.params)

        resp, info = self.api_permissions_create_template(
            name=name,
            description=self.module.params["description"],
            project_key_pattern=self.module.params["project_key_pattern"]
        )

        if info["status"] == 200:
            for group in self.module.params["group_permissions"]:
                for permission in group["permissions"]:
                    self.api_permissions_add_group_to_template(group["group_name"], permission, name)

            for project_creator_permission in self.module.params["project_creator_permissions"]:
                self.api_permissions_add_project_creator_to_template(
                    template_name=name,
                    permission=project_creator_permission
                )

            self.api_permissions_set_default_template(template_name=name)
            self.module.exit_json(changed=True, before={}, after=self.get_permission_template())
        else:
            self.module.fail_json(msg="Unhandled HTTP status %d, please report the bug" % info["status"],
                                  before={}, after=self.get_permission_template())

    def remove_permisson_template(self):
        facts = self.get_permission_template()
        if facts is None:
            self.module.exit_json(changed=False, before={}, after={})
        else:
            # If not in check mode, remove the permission template
            if not self.module.check_mode:
                self.api_permissions_delete_template(name=self.module.params["name"])
            self.module.exit_json(changed=True, before=facts, after={})

    def get_template_groups(self):
        resp, info = self.api_permissions_template_groups(template_name=self.module.params["name"])
        print("resp=%s" % info)
        if resp is not None:
            return resp["groups"]

        return []

    def api_permissions_create_template(self, name, description, project_key_pattern):
        data = {
            "name": name,
            "description": description,
            "projectKeyPattern": project_key_pattern,
        }

        return self.request_sonarqube_api("create_template", method="POST", data=data)

    def api_permissions_update_template(self, id, name, description, project_key_pattern):
        data = {
            "id": id,
            "name": name,
            "description": description,
            "projectKeyPattern": project_key_pattern
        }

        return self.request_sonarqube_api("update_template", method="POST", data=data)

    def api_permissions_delete_template(self, name):
        data = {
            "templateName": name
        }
        return self.request_sonarqube_api("delete_template", method="POST", data=data)

    def api_permissions_add_project_creator_to_template(self, template_name, permission):
        data = {
            "templateName": template_name,
            "permission": permission,
        }

        self.request_sonarqube_api("add_project_creator_to_template", data, "POST")

    def api_permissions_remove_project_creator_from_template(self, template_name, permission):
        data = {
            "templateName": template_name,
            "permission": permission,
        }

        self.request_sonarqube_api("remove_project_creator_from_template", data, "POST")

    def api_permissions_set_default_template(self, template_name):
        data = {
            "templateName": template_name
        }
        return self.request_sonarqube_api("set_default_template", data, "POST")

    def api_permissions_search_templates(self, template_name):
        query = urlencode({"q": template_name})
        return self.request_sonarqube_api("search_templates?%s" % query)

    def api_permissions_template_groups(self, template_name):
        query = urlencode({"templateName": template_name})
        return self.request_sonarqube_api("template_groups?%s" % query)

    def api_permissions_remove_group_from_template(self, group_name, permission, template_name):
        data = {
            "groupName": group_name,
            "permission": permission,
            "templateName": template_name,
        }

        return self.request_sonarqube_api("remove_group_from_template", data, "POST")

    def api_permissions_add_group_to_template(self, group_name, permission, template_name):
        data = {
            "groupName": group_name,
            "permission": permission,
            "templateName": template_name,
        }

        return self.request_sonarqube_api("add_group_to_template", data, "POST")


def main():
    module = AnsibleModule(
        argument_spec=dict(
            state=dict(type='str', choices=['present', 'absent'], default='present'),
            name=dict(required=True, type='str'),
            description=dict(required=False, type='str'),
            default_template=dict(type='bool', default=False),
            project_key_pattern=dict(type='str', default=''),
            group_permissions=dict(required=False, type='list'),
            project_creator_permissions=dict(required=False, type='list'),
            url=dict(type='str', default='http://localhost:9000'),
            user=dict(required=True, type='str', no_log=True),
            password=dict(type='str', no_log=True, default=''),
        ),
        supports_check_mode=True
    )

    module.params['url_username'] = module.params['user']
    module.params['url_password'] = module.params['password']
    module.params['force_basic_auth'] = True
    module.tmpdir = "/tmp"
    sonarqube = SonarqubePermissionTemplateManager(module)
    if module.params['state'] == 'present':
        sonarqube.create_or_update_permission_template()
    elif module.params['state'] == 'absent':
        sonarqube.remove_permisson_template()


if __name__ == '__main__':
    main()
