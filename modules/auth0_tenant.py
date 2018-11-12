#!/usr/bin/python3

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

# -*- coding: utf-8 -*-
DOCUMENTATION = '''
---
module: auth0_tenant

description: Module to update 'tenant' object in Auth0

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
    content_file:
        description:
            - The mode the module is being requested to operate in. Current options are 'get', 'assert' and 'get_all'
        required:
    app_url:
        description:
            - The url of ... <open question to @ivan>
        required: false
    app_url_placeholder:
        description:
            - The placeholder used in the json configuration file used to denote where app_url is to be used.
        required: false
    s3_url:
        description:
            -
        required: false
    s3_url_placeholder:
        description:
            -
        required: false

author:
    - James Armstrong (@nomadicj)
'''

EXAMPLES = '''

- name: Get full config for an Auth0 tenant
  auth0_tenant:
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

#import requests
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
    def get_tenant(self):
        return self.auth0.tenants.get()

    @tenacity.retry(wait=tenacity.wait_fixed(5), stop=tenacity.stop_after_delay(10), retry=tenacity.retry_if_exception_type(Auth0Error))
    def update_tenant(self, body):
        return self.auth0.tenants.update(body)

def run_module():
    module_args = dict(
        domain              = dict(required=True, type='str'),
        clientid            = dict(required=True, type='str'),
        clientsecret        = dict(required=True, type='str'),
        state               = dict(default='present', choices=['present','absent'], type='str'),
        input_file          = dict(type='path'),
        mode                = dict(default='get', choices=['get','assert'], type='str'),
        output_file         = dict(type='path'),
        content_file        = dict(type='str'),
        app_url             = dict(type='str'),
        app_url_placeholder = dict(type='str'),
        s3_url              = dict(type='str'),
        s3_url_placeholder  = dict(type='str'),
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
    content_file = module.params.get('content_file')
    app_url = module.params.get('app_url')
    app_url_placeholder = module.params.get('app_url_placeholder')
    s3_url = module.params.get('s3_url')
    s3_url_placeholder = module.params.get('s3_url_placeholder')


    if module.check_mode:
        result = "Check not currently supported."
        return result

    try:
        auth0 = Auth0(domain = domain, clientid = clientid, clientsecret = clientsecret)
    except Exception as e:
        result['message'].append("Failed to authenticate to Auth0 domain [{}] with following error: [{}]".format(domain, e))
        result['skipped'] = True
        module.exit_json(**result)

    if mode == "get":
        data = auth0.get_tenant()
        export_json = json.dumps(data, indent=2)
        if export_json:
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            with open(output_file, "w") as jsonfile:
                jsonfile.write(export_json)
        else:
            result['message'].append("Nothing returned [{}]".format(export_json))

    if mode == "assert":
        try:
            with open(input_file) as json_data:
                import_json = json.load(json_data)
        except FileNotFoundError as e:
            result['message'].append("{} thrown. No assertion possible.".format(e))
            result['skipped'] = True
            module.exit_json(**result)

        if content_file:
            with open(content_file, "r") as contentfile:
                content_data = contentfile.read()
                if s3_url and s3_url_placeholder:
                    content_data = content_data.replace(s3_url_placeholder, s3_url)
                else:
                    result['message'].append("No s3_url was provided. No attempt at interpolation attempted.")
            import_json['change_password']['html'] = content_data
        else:
            import_json['change_password'].pop('html', None)
            result['message'].append("No content_file was provided. No attempt at implementing to replace existing content made.")
            result['skipped'] = True

        if app_url:
            json_string = json.dumps(import_json).replace(app_url_placeholder, app_url)
            json_string = json_string.replace('localhost:','127.0.0.1:') # Auth0 Tenant API doesn't consider http://localhost:PORT as a valid URL
            import_json = json.loads(json_string)
        else:
            result['message'].append("No app_url was provided. No attempt at interpolation attempted.")

        existing_json = auth0.get_tenant()

        json_diff = DeepDiff(existing_json, import_json, ignore_order=True)
        result['message'].append("{}".format(json_diff))

        if json_diff.get('values_changed', False) or json_diff.get('iterable_item_added', False) or json_diff.get('iterable_item_removed', False) or json_diff.get('dictionary_item_added', False) or json_diff.get('type_changes', False):
            auth0.update_tenant(import_json)
            result['msg'] = ("Updated Tenant")
            if json_diff.get('values_changed', False):
                result['message'].append(json_diff.get('values_changed'))
            if json_diff.get('iterable_item_added', False):
                result['message'].append("iterable_item_added: {}.".format(json_diff.get('iterable_item_added')))
            if json_diff.get('iterable_item_removed', False):
                result['message'].append("iterable_item_removed: {}.".format(json_diff.get('iterable_item_removed')))
            if json_diff.get('dictionary_item_added', False):
                result['message'].append("iterable_item_removed: {}.".format(json_diff.get('dictionary_item_added')))
            result['changed'] = True
        else:
            result['msg'] = ("No change detected")


    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()
