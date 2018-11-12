#!/usr/bin/python3

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

# -*- coding: utf-8 -*-
DOCUMENTATION = '''
---
module: auth0_email

description: Module to implement 'email' object in Auth0

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
    mode:
        description:
            - The mode the module is being requested to operate in. Current options are 'get', 'assert'
        required: false
    smtp_host:
        description:
            - SMTP Server URL detail for using the Email Service Provider required.
        required: false
    smtp_port:
        description:
            - SMTP Server Port Number (typically 25, 465 or 587) detail for using the Email Service Provider required.
        required: false
    smtp_user:
        description:
            - SMTP User detail for using the Email Service Provider required.
        required: false
    smtp_pass:
        description:
            - SMTP Password detail for using the Email Service Provider required.
        required: false
    esp_connection:
        description:
            - Connection type required.
        options: [mandrill, sendgrid, sparkpost, ses, smtp]
        required: false

author:
    - James Armstrong (@nomadicj)
'''

EXAMPLES = '''
- name: Get full config of the email service configured in Auth0
  auth0_email:
    mode: 'get'
    name: '<clientName>'
    domain: '<tenantDomain>'
    clientid: '<clientID>'
    clientsecret: '<clientSecret>'
    output_file: '<outputFile location>'

- name: Set full config of the email service configured in Auth0
  auth0_email:
    mode: 'assert'
    name: '<clientName>'
    domain: '<tenantDomain>'
    clientid: '<clientID>'
    clientsecret: '<clientSecret>'
    input_file: '<inputtFile location>'

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
    def get_email(self):
        return self.auth0.emails.get()

    # @tenacity.retry(wait=tenacity.wait_fixed(5), stop=tenacity.stop_after_delay(10), retry=tenacity.retry_if_exception_type(Auth0Error))
    def update_email(self, body):
        return self.auth0.emails.update(body)

    # @tenacity.retry(wait=tenacity.wait_fixed(5), stop=tenacity.stop_after_delay(10), retry=tenacity.retry_if_exception_type(Auth0Error))
    def create_email(self, body):
        return self.auth0.emails.config(body)

    @tenacity.retry(wait=tenacity.wait_fixed(5), stop=tenacity.stop_after_delay(10), retry=tenacity.retry_if_exception_type(Auth0Error))
    def delete_email(self):
        return self.auth0.emails.delete()

def run_module():
    module_args = dict(
        domain              = dict(required=True, type='str'),
        clientid            = dict(required=True, type='str'),
        clientsecret        = dict(required=True, type='str'),
        state               = dict(default='present', choices=['present','absent'], type='str'),
        input_file          = dict(type='path'),
        mode                = dict(default='get', choices=['get','assert','delete'], type='str'),
        output_file         = dict(type='path'),
        smtp_host           = dict(type='str'),
        smtp_port           = dict(type='str'),
        smtp_user           = dict(type='str'),
        smtp_pass           = dict(type='str'),
        esp_connection      = dict(default='smtp', choices=['mandrill', 'sendgrid', 'sparkpost', 'ses', 'smtp'], type='str'),
        accessKeyId         = dict(type='str'),
        secretAccessKey     = dict(type='str'),
        region              = dict(type='str'),
        default_from_address    = dict(type='str')
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
    input_file      = module.params.get('input_file')
    mode            = module.params.get('mode')
    output_file     = module.params.get('output_file')
    smtp_host       = module.params.get('smtp_host')
    smtp_port       = module.params.get('smtp_port')
    smtp_user       = module.params.get('smtp_user')
    smtp_pass       = module.params.get('smtp_pass')
    esp_connection  = module.params.get('esp_connection')
    accessKeyId     = module.params.get('accessKeyId')
    secretAccessKey = module.params.get('secretAccessKey')
    region          = module.params.get('region')
    default_from_address = module.params.get('default_from_address')

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
        if output_file:
            data = auth0.get_email()
            export_json = json.dumps(data, indent=2)
            if export_json:
                os.makedirs(os.path.dirname(output_file), exist_ok=True)
                with open(output_file, "w") as jsonfile:
                    jsonfile.write(export_json)
            else:
                result['message'].append("Nothing returned [{}]".format(export_json))
        else:
            result['message'].append("Nothing to do; no output_file specified")

    if mode == "delete":
        try:
            auth0.get_email()
        except:
            result['message'].append("No configuration in place. Nothing to delete. Skipping...")
            result['skipped'] = True
            module.exit_json(**result)

        try:
            auth0.delete_email()
            result['results'].append("Deleted ESP configuration")
            result['changed'] = True
        except Exception as e:
            result['message'].append("[{}] thrown. Was not able to remove ESP configuration.".format(e))
            result['skipped'] = True
            module.exit_json(**result)

    if mode == "assert":
        try:
            with open(input_file, "r") as jsonfile:
                import_json = json.load(jsonfile)

            if import_json['enabled'] == True:
                if import_json['name'] == "smtp":
                    result['message'].append("SMTP vars are [{}, {}, {} and {}]".format(smtp_host, smtp_port, smtp_user, smtp_pass))
                    if import_json['credentials']:
                        if False in (smtp_host, smtp_port, smtp_user, smtp_pass):
                            raise Exception('Expected value not populated in ESP config')
                        import_json['credentials']['smtp_host'] = smtp_host
                        import_json['credentials']['smtp_port'] = int(smtp_port)
                        import_json['credentials']['smtp_user'] = smtp_user
                        import_json['credentials']['smtp_pass'] = smtp_pass

                elif import_json['name'] == "mandrill" or import_json['name'] == "sendgrid" or import_json['name'] == "sparkpost":
                    if import_json['credentials']:
                        if False in (api_key):
                            raise Exception('Expected value not populated in ESP config')
                        import_json['credentials']['api_key'] = api_key

                elif import_json['name'] == "ses":
                    if import_json['credentials']:
                        if False in (accessKeyId, secretAccessKey, region):
                            raise Exception('Expected value not populated in ESP config')
                        import_json['credentials']['accessKeyId'] = accessKeyId
                        import_json['credentials']['secretAccessKey'] = secretAccessKey
                        import_json['credentials']['region'] = region

                if default_from_address:
                    import_json['default_from_address'] = default_from_address
                else:
                    result['message'].append("No email_from was provided. No attempt at interpolation attempted.")

            result['message'].append("JSON about to written is [{}]".format(import_json))

            try:
                existing_json = auth0.get_email()
                json_diff = DeepDiff(existing_json, import_json, ignore_order=True)
                result['message'].append("{}".format(json_diff))

                if json_diff.get('values_changed', False) or json_diff.get('iterable_item_added', False) or json_diff.get('iterable_item_removed', False) or json_diff.get('dictionary_item_added', False) or json_diff.get('type_changes', False):
                    auth0.update_email(import_json)
                    result['results'].append("Updated Email Provider")
                    result['message'].append(json_diff.get('values_changed'))
                    result['changed'] = True
                else:
                    result['results'].append("No change detected")
            except Exception as ex:
                try:
                    result['message'].append("{} thrown. No assertion possible.".format(ex))
                    auth0.create_email(import_json)
                    result['results'].append("Created Email Provider")
                    result['changed'] = True
                except Exception as e:
                    result['message'].append("{} thrown. No assertion possible.".format(e))
                    result['skipped'] = True
                    module.exit_json(**result)

        except FileNotFoundError as e:
            result['message'].append("{} thrown. No assertion possible.".format(e))
            result['skipped'] = True
            module.exit_json(**result)

    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()
