#!/usr/bin/python3

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

# -*- coding: utf-8 -*-
DOCUMENTATION = '''
---
module: auth0_rules

description: Module to implement 'rules' object in Auth0

options:
    domain:
        description:
            - The Auth0 tenant specific domain to be interacted with
        required: true
    clientid:
        description:
            - The Auth0 clientId being used for authentication
        required: true
    clientsecret:
        description:
            - The Auth0 clientSecret being used for authentication
        required: true
    input_file:
        description:
            - The file from which to read the changeset to be applied. Required for setting operations.
        required: false
    output_file:
        description:
            - The file to which to write requested outputs. Required for getting operations.
        required:
    mode:
        description:
            - The mode the module is being requested to operate in. Current options are 'get', 'assert' and 'get_all'
        required:
    script_file:
        description:
            - The mode the module is being requested to operate in. Current options are 'get', 'assert' and 'get_all'
        required:
    name:
        description:
            - The mode the module is being requested to operate in. Current options are 'get', 'assert' and 'get_all'
        required:
    tenant:
        description:
            - The mode the module is being requested to operate in. Current options are 'get', 'assert' and 'get_all'
        required:
    tenant_placeholder:
        description:
            - The mode the module is being requested to operate in. Current options are 'get', 'assert' and 'get_all'
        required:

author:
    - James Armstrong (@nomadicj)
'''

EXAMPLES = '''
- name: Get all rules instances for a given Auth0 tenant
  auth0_rules:
    mode: 'get_all'
    domain: '<tenantDomain>'
    clientid: '<clientID>'
    clientsecret: '<clientSecret>'
    output_file: '<outputFile location'

- name: Get full config for a specific instance of an Auth0 rule
  auth0_rules:
    mode: 'get'
    name: '<ruleName>'
    domain: '<tenantDomain>'
    clientid: '<clientID>'
    clientsecret: '<clientSecret>'
    output_file: '<outputFile location>'

'''

from ansible.module_utils.basic import AnsibleModule
from auth0.v3.authentication import GetToken
from auth0.v3.management import Auth0 as a0
from auth0.v3.exceptions import Auth0Error
import tenacity
import json
import os
from deepdiff import DeepDiff

class Auth0(object):
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)
        self.auth0  = self._authenticate()

    def _authenticate(self):
        get_token = GetToken(self.domain)
        token = get_token.client_credentials(self.clientid,
            self.clientsecret, 'https://{}/api/v2/'.format(self.domain))
        return a0(self.domain, token['access_token'])

    @tenacity.retry(wait=tenacity.wait_fixed(5), stop=tenacity.stop_after_delay(10), retry=tenacity.retry_if_exception_type(Auth0Error))
    def get_rules(self):
        return self.auth0.rules.all()

    @tenacity.retry(wait=tenacity.wait_fixed(5), stop=tenacity.stop_after_delay(10), retry=tenacity.retry_if_exception_type(Auth0Error))
    def get_rule(self, id):
        return self.auth0.rules.get(id)

    @tenacity.retry(wait=tenacity.wait_fixed(5), stop=tenacity.stop_after_delay(10), retry=tenacity.retry_if_exception_type(Auth0Error))
    def update_rule(self, id, body):
        return self.auth0.rules.update(id, body)

    # @tenacity.retry(wait=tenacity.wait_fixed(5), stop=tenacity.stop_after_delay(10), retry=tenacity.retry_if_exception_type(Auth0Error))
    def create_rule(self, body):
        return self.auth0.rules.create(body)

    @tenacity.retry(wait=tenacity.wait_fixed(5), stop=tenacity.stop_after_delay(10), retry=tenacity.retry_if_exception_type(Auth0Error))
    def delete_rule(self, id):
        return self.auth0.rules.delete(id)

    @tenacity.retry(wait=tenacity.wait_fixed(5), stop=tenacity.stop_after_delay(10), retry=tenacity.retry_if_exception_type(Auth0Error))
    def get_rule_id(self, name):
        for rule in self.auth0.rules.all():
            if rule['name'] == name:
                return rule['id']
        for rule in self.auth0.rules.all(enabled=False):
            if rule['name'] == name:
                return rule['id']
        return False


def run_module():
    module_args = dict(
        domain              = dict(required=True, type='str'),
        clientid            = dict(required=True, type='str'),
        clientsecret        = dict(required=True, type='str'),
        state               = dict(default='present', choices=['present','absent'], type='str'),
        input_file          = dict(type='path'),
        mode                = dict(default='get', choices=['get_all','get','assert'], type='str'),
        output_file         = dict(type='path'),
        script_file         = dict(type='str'),
        name                = dict(type='str'),
        tenant_name         = dict(type='str'),
        tenant_name_placeholder     = dict(type='str'),
        webtask_api_key     = dict(type='str'),
        webtask_api_key_placeholder = dict(type='str')
    )

    result = dict(
        changed = False,
        failed = False,
        msg = '',
        results = [],
        skipped = False,
        message = []
    )

    module = AnsibleModule(
        argument_spec       = module_args,
        supports_check_mode = True,
    )

    domain = module.params.get('domain')
    clientid = module.params.get('clientid')
    clientsecret = module.params.get('clientsecret')
    input_file = module.params.get('input_file')
    mode = module.params.get('mode')
    output_file = module.params.get('output_file')
    script_file = module.params.get('script_file')
    name = module.params.get('name')
    tenant_name = module.params.get('tenant_name')
    tenant_name_placeholder = module.params.get('tenant_name_placeholder')
    webtask_api_key = module.params.get('webtask_api_key')
    webtask_api_key_placeholder = module.params.get('webtask_api_key_placeholder')

    if module.check_mode:
        result = "Check not currently supported."
        return result

    try:
        auth0 = Auth0(domain = domain, clientid = clientid, clientsecret = clientsecret)
    except Exception as e:
        result['message'].append("Failed to authenticate to Auth0 domain [{}] with following error: [{}]".format(domain, e))
        result['skipped'] = True
        module.exit_json(**result)

    if mode == "get_all":
        if output_file:
            data = auth0.get_rules()
            export_json = json.dumps(data, indent=2)
            if export_json:
                os.makedirs(os.path.dirname(output_file), exist_ok=True)
                with open(output_file, "w") as jsonfile:
                    jsonfile.write(export_json)
            else:
                result['message'].append("Nothing returned [{}]".format(export_json))
        else:
            result['message'].append("Nothing to do; no output_file specified")

    if mode == "get":
        if output_file:
            data = auth0.get_rule()
            export_json = json.dumps(data, indent=2)
            if export_json:
                os.makedirs(os.path.dirname(output_file), exist_ok=True)
                with open(output_file, "w") as jsonfile:
                    jsonfile.write(export_json)
            else:
                result['message'].append("Nothing returned [{}]".format(export_json))
        else:
            result['message'].append("Nothing to do; no output_file specified")

    if mode == "assert":
        try:
            with open(input_file) as json_data:
                import_json = json.load(json_data)

            with open(script_file, "r") as scriptfile:
                script_body = scriptfile.read()

            tenant_name = domain.split(".")[0]

            if tenant_name and tenant_name_placeholder:
                script_body = script_body.replace(tenant_name_placeholder, tenant_name)
            else:
                result['message'].append("No tenant name and/or tenant name placeholder was available. No attempt at interpolation attempted.")

            if webtask_api_key and webtask_api_key_placeholder:
                script_body = script_body.replace(webtask_api_key_placeholder, webtask_api_key)
            else:
                result['message'].append("No webtask api key and/or webtask api key placeholder was available. No attempt at interpolation attempted.")

            import_json.update(script = script_body)

            try:
                existing_json = auth0.get_rule(auth0.get_rule_id(name))
                try:
                    json_diff = DeepDiff(existing_json, import_json, ignore_order=True)
                    result['message'].append("{}".format(json_diff))

                    if json_diff.get('values_changed', False) or json_diff.get('iterable_item_added', False) or json_diff.get('iterable_item_removed', False) or json_diff.get('dictionary_item_added', False) or json_diff.get('type_changes', False):
                        try:
                            import_json.pop("id")
                        except KeyError:
                            result['message'].append("{}".format("Key not found"))
                        auth0.update_rule(existing_json['id'], import_json)
                        result['results'].append("Updated RuleId [{}] with name [{}]".format(existing_json['id'], existing_json['name']))
                        result['message'].append(json_diff.get('values_changed'))
                        result['changed'] = True
                    else:
                        result['results'].append("No change detected")
                except Exception as e:
                    result['message'].append("Update failed. [{}] No assertion possible.".format(e))
                    result['skipped'] = True
                    module.exit_json(**result)
            except Exception as e:
                try:
                    auth0.create_rule(import_json)
                    result['results'].append("Added Rule [{}]".format(name))
                    result['changed'] = True
                except Exception as e:
                    result['message'].append("Create failed. [{}] thrown. No assertion possible.".format(e))
                    result['skipped'] = True
                    module.exit_json(**result)

        except Exception as e:
            result['message'].append("Assert failed. [{}] No assertion possible.".format(e))
            result['skipped'] = True
            module.exit_json(**result)
    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()
