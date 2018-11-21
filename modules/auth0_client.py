#!/usr/bin/python3

ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'community'
}

# -*- coding: utf-8 -*-
DOCUMENTATION = '''
---
module: auth0_client

description: Module to implement 'client' object in Auth0

options:
    name:
        description:
            - The name of the client to be acted upon
        required: true
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
    content_file:
        description:
            - The file in which html content to be inserted into the config is independently stored.
        required:

author:
    - James Armstrong (@nomadicj)
'''

EXAMPLES = '''
- name: Get all clients for a given Auth0 tenant
  auth0_client:
    mode: 'get_all'
    domain: '<tenantDomain>'
    clientid: '<clientID>'
    clientsecret: '<clientSecret>'
    output_file: 'output/client.json'

- name: Get full config for a specific Auth0 tenant
  auth0_client:
    mode: 'get'
    name: '<clientName>'
    domain: '<tenantDomain>'
    clientid: '<clientID>'
    clientsecret: '<clientSecret>'
    output_file: 'output/client.json'

- name: Get full config for a specific Auth0 tenant
  auth0_client:
    mode: 'assert'
    name: '<clientName>'
    domain: '<tenantDomain>'
    clientid: '<clientID>'
    clientsecret: '<clientSecret>'
    input_file: '<inputFile>'
    content_file: '<contentFile>'
    app_url: '<applicationUrl>'
    app_url_placeholder: '<string>'
'''

from ansible.module_utils.basic import AnsibleModule
from auth0.v3.authentication import GetToken
from auth0.v3.management import Auth0 as a0
from auth0.v3.exceptions import Auth0Error
import json
import os
from deepdiff import DeepDiff
import hashlib

class Auth0(object):
    def __init__(self, **kwargs):
        self.__dict__.update(kwargs)
        self.auth0  = self._authenticate()

    def _authenticate(self):
        get_token = GetToken(self.domain)
        token = get_token.client_credentials(self.clientid,
            self.clientsecret, 'https://{}/api/v2/'.format(self.domain))
        return a0(self.domain, token['access_token'])

    def get_clients(self):
        return self.auth0.clients.all()

    def get_client(self, client_id):
        return self.auth0.clients.get(client_id)

    def create_client(self, body):
        return self.auth0.clients.create(body)

    def update_client(self, client_id, body):
        return self.auth0.clients.update(client_id, body)

    def delete_client(self, client_id):
        return self.auth0.clients.delete(client_id)

    def get_clientid(self, name):
        for client in self.get_clients():
            if client['name'] == name:
                return client['client_id']
        return False

def check_json_diff():
    # Build new JSON
    try:
        with open(input_file) as json_data:
            import_json = json.load(json_data)

        with open(content_file, "r") as contentfile:
            content_data = contentfile.read()

        if s3_url and s3_url_placeholder:
            content_data = content_data.replace(s3_url_placeholder, s3_url)
        else:
            result['message'].append("No s3_url was available. No attempt at interpolation attempted.")

        if custom_domain and custom_domain_placeholder:
            content_data = content_data.replace(custom_domain_placeholder, custom_domain)
        else:
            result['message'].append("No Custom Domain was available. No attempt at interpolation attempted.")

        import_json.update(custom_login_page = content_data)

        if app_url and app_url_placeholder:
            json_string = json.dumps(import_json).replace(app_url_placeholder, app_url)
            import_json = json.loads(json_string)
        else:
            result['message'].append("No app_url was provided. No attempt at interpolation attempted.")
    except Exception as e:
        result['message'].append("{} thrown. No assertion possible.".format(e))
        result['skipped'] = True
        module.exit_json(**result)

    #  Get existing JSON
    try:
        client_id = auth0.get_clientid(name)
        existing_json = auth0.get_client(client_id)
        content_hash_change = False
    except Exception as e:
        result['message'].append("{} thrown. No assertion possible.".format(e))
        result['skipped'] = True
        module.exit_json(**result)

    try:
        new_content_hash = hashlib.sha256(content_data.encode('utf-8')).hexdigest()
        old_content_hash = hashlib.sha256(existing_json.encode('utf-8')).hexdigest()

        result['message'].append("Old custom_login_page hash; [{}]".format(old_content_hash))
        result['message'].append("New custom_login_page hash; [{}]".format(new_content_hash))

        existing_json.get('description', False)
        old_content_hash = old_content_hash.split(":")[-1]

        if new_content_hash != old_content_hash:
            result['message'].append("[{}] file change detected.".format("custom_login_page"))
            # content_hash_change = True
            # import_json.update(description="custom_login_page:{}".format(new_content_hash))
    except Exception as e:
        result['message'].append("Failed to assess new vs old content files.")

    json_diff = DeepDiff(existing_json, import_json, ignore_order=True)
    except Exception as e:
        result['message'].append("{} thrown. No assertion possible.".format(e))
        result['skipped'] = True
        module.exit_json(**result)

def run_module():
    module_args = dict(
        domain                  = dict(required=True, type='str'),
        clientid                = dict(required=True, type='str'),
        clientsecret            = dict(required=True, type='str'),
        name                    = dict(type='str'),
        state                   = dict(default='present', choices=['present','absent'], type='str'),
        input_file              = dict(type='path'),
        mode                    = dict(default='get', choices=['get','assert','get_all'], type='str'),
        output_file             = dict(type='path'),
        app_url                 = dict(type='str'),
        app_url_placeholder     = dict(type='str'),
        s3_url                  = dict(type='str'),
        s3_url_placeholder      = dict(type='str'),
        content_file            = dict(type='str'),
        custom_domain           = dict(type='str'),
        custom_domain_placeholder = dict(type='str')
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

    domain                      = module.params.get('domain')
    clientid                    = module.params.get('clientid')
    clientsecret                = module.params.get('clientsecret')
    name                        = module.params.get('name')
    input_file                  = module.params.get('input_file')
    mode                        = module.params.get('mode')
    output_file                 = module.params.get('output_file')
    app_url                     = module.params.get('app_url')
    app_url_placeholder         = module.params.get('app_url_placeholder')
    content_file                = module.params.get('content_file')
    s3_url                      = module.params.get('s3_url')
    s3_url_placeholder          = module.params.get('s3_url_placeholder')
    custom_domain               = module.params.get('custom_domain')
    custom_domain_placeholder   = module.params.get('custom_domain_placeholder')


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
        try:
            client_id = auth0.get_clientid(name)
            if not client_id:
                raise ValueError('No client returned when [{}] passed.'.format(name))

            client_data = auth0.get_client(client_id)

            for key in ('signing_keys', 'client_secret'):
                client_data.pop(key, None)

            client_json = json.dumps(client_data, indent=2)
            if output_file:
                os.makedirs(os.path.dirname(output_file), exist_ok=True)
                with open(output_file, "w") as jsonfile:
                    jsonfile.write(client_json)
                result['results'].append("Client JSON written to [{}]".format(output_file))
            else:
                result['results'].append(client_data)
        except Exception as e:
            result['message'].append("{} No get possible.".format(e))

    if mode == "get_all":
        client_list = auth0.get_clients()
        for client in client_list:
            result['results'].append('{}:{}'.format(client['name'], client['client_id']))

    if mode == "check":
        json_diff = check_json_diff()

    if mode == "assert":
        try:
            with open(input_file) as json_data:
                import_json = json.load(json_data)

            with open(content_file, "r") as contentfile:
                content_data = contentfile.read()

            if s3_url and s3_url_placeholder:
                content_data = content_data.replace(s3_url_placeholder, s3_url)
            else:
                result['message'].append("No s3_url was available. No attempt at interpolation attempted.")

            if custom_domain and custom_domain_placeholder:
                content_data = content_data.replace(custom_domain_placeholder, custom_domain)
            else:
                result['message'].append("No Custom Domain was available. No attempt at interpolation attempted.")

            import_json.update(custom_login_page = content_data)

            if app_url and app_url_placeholder:
                json_string = json.dumps(import_json).replace(app_url_placeholder, app_url)
                import_json = json.loads(json_string)
            else:
                result['message'].append("No app_url was provided. No attempt at interpolation attempted.")

            try:
                client_id = auth0.get_clientid(name)
                existing_json = auth0.get_client(client_id)
                content_hash_change = False

                try:
                    new_content_hash = hashlib.sha256(content_data.encode('utf-8')).hexdigest()
                    old_content_hash = hashlib.sha256(existing_json.encode('utf-8')).hexdigest()

                    result['message'].append("Old custom_login_page hash; [{}]".format(old_content_hash))
                    result['message'].append("New custom_login_page hash; [{}]".format(new_content_hash))

                    existing_json.get('description', False)
                    old_content_hash = old_content_hash.split(":")[-1]

                    if new_content_hash != old_content_hash:
                        result['message'].append("[{}] file change detected.".format("custom_login_page"))
                        # content_hash_change = True
                        # import_json.update(description="custom_login_page:{}".format(new_content_hash))
                except Exception as e:
                    result['message'].append("Failed to assess new vs old content files.")

                json_diff = DeepDiff(existing_json, import_json, ignore_order=True)
                result['message'].append("{}".format(json_diff))

                if json_diff.get('values_changed', False) or json_diff.get('iterable_item_added', False) or json_diff.get('iterable_item_removed', False) or json_diff.get('dictionary_item_added', False) or json_diff.get('type_changes', False) or content_hash_change:
                    auth0.update_client(client_id, import_json)
                    result['results'].append("Updated ClientID [{}]".format(client_id))
                    if json_diff.get('values_changed', False):
                        result['message'].append(json_diff.get('values_changed'))
                    if json_diff.get('iterable_item_added', False):
                        result['message'].append("iterable_item_added: {}.".format(json_diff.get('iterable_item_added')))
                    if json_diff.get('iterable_item_removed', False):
                        result['message'].append("iterable_item_removed: {}.".format(json_diff.get('iterable_item_removed')))
                    if content_hash_change:
                        result['message'].append("Content file hash updated from {} to {}.".format(old_content_hash, new_content_hash))
                    result['changed'] = True
                else:
                    result['results'].append("No change detected")
            except Exception as e:
                try:
                    auth0.create_client(import_json)
                    result['results'].append("Added Client [{}]".format(name))
                    result['changed'] = True
                except Exception as e:
                    result['message'].append("{} thrown. No assertion possible.".format(e))
                    result['skipped'] = True
                    module.exit_json(**result)

        except Exception as e:
            result['message'].append("{} thrown. No assertion possible.".format(e))
            result['skipped'] = True
            module.exit_json(**result)

    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()
