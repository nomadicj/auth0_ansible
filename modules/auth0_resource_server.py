#!/usr/bin/python3

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

# -*- coding: utf-8 -*-
DOCUMENTATION = '''
---
module: auth0_resource_server

description: Module to implement 'resource_server' object in Auth0

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

author:
    - James Armstrong (@nomadicj)
'''

EXAMPLES = '''
- name: Get all resource_server instances for a given Auth0 tenant
  auth0_resource_server:
    mode: 'get_all'
    domain: '<tenantDomain>'
    clientid: '<clientID>'
    clientsecret: '<clientSecret>'
    output_file: '<outputFile location'

- name: Get full config for a specific Auth0 resource_server
  auth0_resource_server:
    mode: 'get'
    name: '<clientName>'
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
    def get_resource_servers(self):
        return self.auth0.resource_servers.get_all()

    @tenacity.retry(wait=tenacity.wait_fixed(5), stop=tenacity.stop_after_delay(10), retry=tenacity.retry_if_exception_type(Auth0Error))
    def get_resource_server(self, id):
        return self.auth0.resource_servers.get(id)

    @tenacity.retry(wait=tenacity.wait_fixed(5), stop=tenacity.stop_after_delay(10), retry=tenacity.retry_if_exception_type(Auth0Error))
    def update_resource_server(self, id, body):
        return self.auth0.resource_servers.update(id, body)

    @tenacity.retry(wait=tenacity.wait_fixed(5), stop=tenacity.stop_after_delay(10), retry=tenacity.retry_if_exception_type(Auth0Error))
    def create_resource_server(self, body):
        return self.auth0.resource_servers.create(body)

    def get_resource_server_id(self, identifier):
        for resource_server in self.auth0.resource_servers.get_all():
            if resource_server['identifier'] == identifier:
                return resource_server['id']
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
            data = auth0.get_resource_servers()
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
            data = auth0.get_resource_server()
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
            with open(input_file, "r") as jsonfile:
                import_json = json.load(jsonfile)

            try:
                identifier = import_json['identifier']
                resource_server_id = auth0.get_resource_server_id(identifier)
                existing_json = auth0.get_resource_server(resource_server_id)

                json_diff = DeepDiff(existing_json, import_json, ignore_order=True)
                result['message'].append("{}".format(json_diff))

                if json_diff.get('values_changed', False) or json_diff.get('iterable_item_added', False) or json_diff.get('iterable_item_removed', False) or json_diff.get('dictionary_item_added', False) or json_diff.get('type_changes', False):
                    try:
                        import_json.pop('identifier')
                        auth0.update_resource_server(auth0.get_resource_server_id(identifier), import_json)
                    except Exception as e:
                        result['message'].append("Update resource server fail. {} No assertion possible.".format(e))
                        result['skipped'] = True
                        module.exit_json(**result)
                    result['message'].append("Import JSON; {}".format(import_json))
                    result['results'].append("Updated resource server [name {}, audience {}]".format(import_json['name'], identifier))
                    result['message'].append(json_diff.get('values_changed'))
                    result['changed'] = True
                else:
                    result['results'].append("No change detected")
            except Exception as e:
                try:
                    auth0.create_resource_server(import_json)
                    result['changed'] = True
                except Exception as e:
                    result['message'].append("Create resource server fail. {} No assertion possible.".format(e))
                    result['skipped'] = True
                    module.exit_json(**result)

        except Exception as e:
            result['message'].append("{} thrown. Resource server lookup failed.".format(e))
            result['skipped'] = True
            module.exit_json(**result)

    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()
