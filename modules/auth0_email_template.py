#!/usr/bin/python3

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

# -*- coding: utf-8 -*-
DOCUMENTATION = '''
---
module: auth0_email_template

description: Module to implement 'email_template' object in Auth0

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
        required: false
    content_file:
        description:
            - The file from which to read template specific html.
        required: false
    mode:
        description:
            - The mode the module is being requested to operate in. Current options are 'get', 'assert'
        required: false
    result_url:
        description:
            -
        required: false
    s3_url:
        description:
            -
        required: false
    s3_url_placeholder:
        description:
            -
        required: false
    email_from:
        description:
            -
        required: false

author:
    - James Armstrong (@nomadicj)
'''

EXAMPLES = '''
- name: Get full config for a specific Auth0 email template
  auth0_email_template:
    mode: 'get'
    name: '<clientName>'
    domain: '<tenantDomain>'
    clientid: '<clientID>'
    clientsecret: '<clientSecret>'
    output_file: '<outputFile location>'

- name: Set config for a specific Auth0 email template
  auth0_email_template:
    mode: 'assert'
    name: '<clientName>'
    domain: '<tenantDomain>'
    clientid: '<clientID>'
    clientsecret: '<clientSecret>'
    input_file: '<inputFile location>'
    content_file: '<contentFile location>'

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
    def create_email_template(self, body):
        return self.auth0.email_templates.create(body)

    @tenacity.retry(wait=tenacity.wait_fixed(5), stop=tenacity.stop_after_delay(10), retry=tenacity.retry_if_exception_type(Auth0Error))
    def get_email_template(self, name):
        return self.auth0.email_templates.get(name)

    @tenacity.retry(wait=tenacity.wait_fixed(5), stop=tenacity.stop_after_delay(10), retry=tenacity.retry_if_exception_type(Auth0Error))
    def update_email_template(self, name, body):
        return self.auth0.email_templates.update(name, body)

def run_module():
    module_args = dict(
        domain              = dict(required=True, type='str'),
        clientid            = dict(required=True, type='str'),
        clientsecret        = dict(required=True, type='str'),
        name                = dict(choices=['verify_email', 'reset_email', 'welcome_email', 'blocked_account', 'stolen_credentials', 'enrollment_email', 'mfa_oob_code'], type='str'),
        state               = dict(default='present', choices=['present','absent'], type='str'),
        input_file          = dict(type='path'),
        mode                = dict(default='get', choices=['get','assert'], type='str'),
        output_file         = dict(type='path'),
        content_file        = dict(type='path'),
        result_url          = dict(type='str'),
        s3_url              = dict(type='str'),
        s3_url_placeholder  = dict(type='str'),
        email_from          = dict(type='str')
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

    domain          = module.params.get('domain')
    clientid        = module.params.get('clientid')
    clientsecret    = module.params.get('clientsecret')
    name            = module.params.get('name')
    input_file      = module.params.get('input_file')
    mode            = module.params.get('mode')
    output_file     = module.params.get('output_file')
    content_file    = module.params.get('content_file')
    result_url      = module.params.get('result_url')
    s3_url          = module.params.get('s3_url')
    s3_url_placeholder = module.params.get('s3_url_placeholder')
    email_from      = module.params.get('email_from')

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
        data = auth0.get_email_template(name)
        export_json = json.dumps(data, indent=2)
        if export_json:
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            with open(output_file, "w") as jsonfile:
                jsonfile.write(export_json)
        else:
             result['message'].append("Nothing returned [{}]".format(export_json))

    if mode == "assert":
        try:
            with open(input_file, "r") as jsonfile:
                import_json = json.load(jsonfile)

            with open(content_file, "r") as contentfile:
                content_data = contentfile.read()

            if s3_url and s3_url_placeholder:
                content_data = content_data.replace(s3_url_placeholder, s3_url)
            else:
                result['message'].append("No s3_url was provided. No attempt at interpolation attempted.")

            import_json['body'] = content_data

            if result_url:
                import_json['resultUrl'] = result_url
            else:
                result['message'].append("No result_url was provided. No attempt at interpolation attempted.")

            if email_from:
                import_json['from'] = email_from
            else:
                result['message'].append("No email_from was provided. No attempt at interpolation attempted.")

            try:
                existing_json = auth0.get_email_template(name)
                json_diff = DeepDiff(existing_json, import_json, ignore_order=True)
                result['message'].append("{}".format(json_diff))

                if json_diff.get('values_changed', False) or json_diff.get('iterable_item_added', False) or json_diff.get('iterable_item_removed', False) or json_diff.get('dictionary_item_added', False) or json_diff.get('type_changes', False):
                    try:
                        auth0.update_email_template(name, import_json)
                    except Exception as e:
                        result['message'].append("Update template fail. {} No assertion possible.".format(e))
                        result['skipped'] = True
                        module.exit_json(**result)
                    result['message'].append("Import JSON; {}".format(import_json))
                    result['results'].append("Updated Email Template [{}]".format(name))
                    result['message'].append(json_diff.get('values_changed'))
                    result['changed'] = True
                else:
                    result['results'].append("No change detected")
            except Exception as e:
                try:
                    auth0.create_email_template(import_json)
                    result['changed'] = True
                except Exception as e:
                    result['message'].append("Create template fail. {} No assertion possible.".format(e))
                    result['skipped'] = True
                    module.exit_json(**result)

        except Exception as e:
            result['message'].append("{} thrown. Template lookup failed.".format(e))
            result['skipped'] = True
            module.exit_json(**result)

    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()
