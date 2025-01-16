#!/usr/bin/python

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = r'''
---
module: yc_lockbox

short_description: Manage secrets in Yandex Cloud Lockbox

version_added: "1.0.1"

description:
    - Manage secrets in Yandex Cloud Lockbox using REST API.
    - Supports creating, deleting, and managing secrets with optional delete protection.

options:
    iam_token:
        description:
            - IAM token for authentication.
        required: true
        type: str
    folder_id:
        description:
            - The ID of the folder where the secret is stored.
        required: true
        type: str
    secret_name:
        description:
            - The name of the secret.
        required: true
        type: str
    secret_id:
        description:
            - The ID of the secret.
        required: false
        type: str
        default: ""
    secret_description:
        description:
            - The description of the secret.
        required: false
        type: str
        default: ""
    text_payload_entries:
        description:
            - List of key-value pairs to store in the secret.
            - Each element should be a dictionary with 'key' and 'value' fields.
        required: false
        type: list
        elements: dict
        default: []
    state:
        description:
            - Desired state of the secret.
        required: false
        type: str
        choices: ['present', 'absent', 'update', 'activate', 'deactivate']
        default: 'present'
    delete_protection:
        description:
            - Enable delete protection for the secret.
        required: false
        type: bool
        default: True
    secret_data_file:
        description:
            - Path to a file containing key-value pairs to store in the secret.
            - File parsing as YAML structure.
        required: false
        type: str

author:
    - Nikolay Krasnov (@krang404)
'''

EXAMPLES = r'''
# Create a secret
- name: Create secret
  yc_lockbox:
    iam_token: your_iam_token
    folder_id: your_folder_id
    secret_name: my_secret
    text_payload_entries:
        key1: "value1"
        key2: "value2"
    state: present

# Create a secret with data from file
- name: Create secret with data from file
  yc_lockbox:
    iam_token: your_iam_token
    folder_id: your_folder_id
    secret_name: my_secret
    secret_data_file: /path/to/secret_data_file.txt
    state: present

# Delete a secret
- name: Delete secret
  yc_lockbox:
    iam_token: your_iam_token
    folder_id: your_folder_id
    secret_name: my_secret
    state: absent
'''

RETURN = r'''
id:
    description:
        - The ID of the secret.
    type: str
    returned: always
'''

import yaml
import sys
import os

def check_module_installed(module_name):
    import importlib.util
    if importlib.util.find_spec(module_name) is None:
        raise ImportError(f"The module '{module_name}' is not installed. Install it using 'pip install {module_name}'")

try:
    check_module_installed('yandexcloud')
except ImportError as e:
    print(e)
    sys.exit(1)

from yandexcloud import SDK
from yandex.cloud.lockbox.v1.secret_service_pb2 import CreateSecretRequest, ListSecretsRequest, \
     DeleteSecretRequest, GetSecretRequest, AddVersionRequest, DeactivateSecretRequest, ActivateSecretRequest
     
from yandex.cloud.lockbox.v1.secret_service_pb2_grpc import SecretServiceStub

from ansible.module_utils.basic import AnsibleModule

def create_secret(iam_token, folder_id, secret_name, secret_description, version_payload_entries, delete_protection):
    sdk = SDK(iam_token=iam_token)
    secret_stub = sdk.client(SecretServiceStub)
    create_request = CreateSecretRequest(
        folder_id=folder_id,
        name=secret_name,
        description=secret_description,
        version_payload_entries=version_payload_entries,
        deletion_protection=delete_protection,
    )
    response = secret_stub.Create(create_request)
    return response

def list_secrets(iam_token, folder_id):
    sdk = SDK(iam_token=iam_token)
    secret_stub = sdk.client(SecretServiceStub)
    list_request = ListSecretsRequest(folder_id=folder_id)
    response = secret_stub.List(list_request)
    return response

def get_secret(iam_token, secret_id):
    sdk = SDK(iam_token=iam_token)
    secret_stub = sdk.client(SecretServiceStub)
    get_request= GetSecretRequest(secret_id=secret_id)
    response = secret_stub.Get(get_request)
    return response

def delete_secret(iam_token, secret_id):
    sdk = SDK(iam_token=iam_token)
    secret_stub = sdk.client(SecretServiceStub)
    delete_request = DeleteSecretRequest(secret_id=secret_id)
    operation = secret_stub.Delete(delete_request)
    return operation


def update_secret(iam_token, secret_id, secret_description, version_payload_entries, current_version_id):
    sdk = SDK(iam_token=iam_token)
    secret_stub = sdk.client(SecretServiceStub)
    update_request = AddVersionRequest(
        description=secret_description,
        secret_id=secret_id,
        payload_entries=version_payload_entries,
        base_version_id=current_version_id,
        )
    operation = secret_stub.AddVersion(update_request)
    
    return operation

def activate_secret(iam_token, secret_id):
    sdk = SDK(iam_token=iam_token)
    secret_stub = sdk.client(SecretServiceStub)
    deactivate_request = ActivateSecretRequest(secret_id=secret_id)
    operation = secret_stub.Activate(deactivate_request)    
    return operation

def deactivate_secret(iam_token, secret_id):
    sdk = SDK(iam_token=iam_token)
    secret_stub = sdk.client(SecretServiceStub)
    deactivate_request = DeactivateSecretRequest(secret_id=secret_id)
    operation = secret_stub.Deactivate(deactivate_request)    
    return operation

def load_secret_data_file(file_path):
    with open(file_path, 'r') as f:
        secret_data = yaml.safe_load(f)
        
    if not isinstance(secret_data, dict):
        raise ValueError("YAML file must contain a dictionary at the top level")
    
    def convert_values_to_str_and_filter(data):
        if isinstance(data, dict):
            return {
                key: convert_values_to_str_and_filter(value)
                for key, value in data.items()
                if value not in [None, '', [], {}]
            }
        elif isinstance(data, list):
            return [
                convert_values_to_str_and_filter(item)
                for item in data
                if item not in [None, '', [], {}]  
            ]
        elif isinstance(data, (int, float)):
            return str(data)
        else:
            return data

    secret_data = convert_values_to_str_and_filter(secret_data)

    return secret_data

def main():
    module = AnsibleModule(
        argument_spec = dict(
            iam_token=dict(type='str', required=True, no_log=True),
            folder_id=dict(type='str', required=False),
            secret_name=dict(type='str', required=True),
            secret_id=dict(type='str', required=False, default=''),
            secret_description=dict(type='str', required=False, default=''),
            text_payload_entries=dict(type='dict', required=False, default={}),
            secret_data_file=dict(type='str', required=False, default=''),
            state=dict(type='str', choices=['present', 'absent', 'update', 'deactivate', 'activate'], default='present'),
            delete_protection=dict(type='bool', required=False, default=True),
            ),
        supports_check_mode=True
    )

    iam_token = module.params['iam_token']
    folder_id = module.params['folder_id']
    secret_name = module.params['secret_name']
    secret_id = module.params['secret_id']
    secret_description = module.params['secret_description']
    text_payload_entries = module.params['text_payload_entries']
    secret_data_file = module.params['secret_data_file']
    state = module.params['state']
    delete_protection = module.params['delete_protection']
    
    STATUS_MAPPING = {
        0: "STATUS_UNSPECIFIED",
        1: "CREATING",
        2: "ACTIVE",
        3: "INACTIVE"
        }

    try:
        combined_secret_data = text_payload_entries.copy()

        if secret_data_file:
            real_path = os.path.realpath(secret_data_file)
            secret_data_from_file = load_secret_data_file(real_path)
            for key in secret_data_from_file:
                if key in combined_secret_data:
                    module.fail_json(msg=f"Duplicate key '{key}' found in both text_payload_entries and secret_data_file.")
            combined_secret_data.update(secret_data_from_file)

        version_payload_entries = [{'key': key, 'text_value': value} for key, value in combined_secret_data.items()]
        if len(version_payload_entries) > 32:
            raise ValueError("The number of keys in version_payload_entries exceeds the limit of 32.")

        if module.check_mode:
            module.exit_json(
                changed=True,
                msg=f"Check mode: Action '{state}' would be performed for secret '{secret_name}'"
            )

        if state == 'present':
            if not secret_id:
                secrets_response = list_secrets(iam_token, folder_id)
                for secret in secrets_response.secrets:
                    if secret.name == secret_name:
                        module.fail_json(msg=f"Secret with the same name already exists: {secret_name}")
            
            response = create_secret(iam_token, folder_id, secret_name, secret_description, version_payload_entries, delete_protection)
            module.exit_json(changed=True, id=response.id)
        
        elif state == 'absent':
            if not secret_id:
                secrets_response = list_secrets(iam_token, folder_id)

                if not secrets_response.secrets:
                    module.fail_json(msg="No secrets in Lockbox")


                matching_secrets = [
                    secret for secret in secrets_response.secrets if secret.name == secret_name
                ]

                if len(matching_secrets) == 0:
                    module.fail_json(msg=f"Secret with name '{secret_name}' not found")
                elif len(matching_secrets) > 1:
                    module.fail_json(msg=f"Multiple secrets found with name: {secret_name}")
                
                secret_id = matching_secrets[0].id
                    
          
            delete_secret(iam_token, secret_id)
            module.exit_json(changed=True)
            
        elif state == 'update':
            if not secret_id:
                secrets_response = list_secrets(iam_token, folder_id)
                if not secrets_response.secrets:
                    module.fail_json(msg="No secrets in Lockbox")

                matching_secrets = [
                    secret for secret in secrets_response.secrets if secret.name == secret_name
                ]

                if len(matching_secrets) == 0:
                    module.fail_json(msg=f"Secret with name '{secret_name}' not found")
                elif len(matching_secrets) > 1:
                    module.fail_json(msg=f"Secret with the same name already exists: {secret_name} \nPlease, set secret_id for update correct secret!")
                
                secret_id = matching_secrets[0].id
                current_version_id = matching_secrets[0].current_version.id
            elif secret_id:
                secrets_response = get_secret(iam_token, secret_id)
                current_version_id = secrets_response.current_version.id
           
            update_secret(iam_token, secret_id, secret_description, version_payload_entries, current_version_id)
            module.exit_json(changed=True)
             

        elif state == 'deactivate':

            if not secret_id:
                secrets_response = list_secrets(iam_token, folder_id)
                if not secrets_response.secrets:
                    module.fail_json(msg="No secrets in Lockbox")

                matching_secrets = [
                    secret for secret in secrets_response.secrets if secret.name == secret_name
                ]

                if len(matching_secrets) == 0:
                    module.fail_json(msg=f"Secret with name '{secret_name}' not found")
                elif len(matching_secrets) > 1:
                    module.fail_json(msg=f"Secret with the same name already exists: {secret_name} \nPlease, set secret_id for update correct secret!")
                
                secret_id = matching_secrets[0].id

            secrets_response = get_secret(iam_token, secret_id)
            secret_status_code = secrets_response.status
            secret_status = STATUS_MAPPING.get(secret_status_code, "UNKNOWN_STATUS")
            
            if secret_status == 'ACTIVE':
                deactivate_secret(iam_token, secret_id)
                module.exit_json(changed=True)
            else:
                module.fail_json(msg=f"Deactivation impossble because secret is {secret_status} now!")
                
        elif state == 'activate':
            if not secret_id:
                secrets_response = list_secrets(iam_token, folder_id)
                if not secrets_response.secrets:
                    module.fail_json(msg="No secrets in Lockbox")

                matching_secrets = [
                    secret for secret in secrets_response.secrets if secret.name == secret_name
                ]

                if len(matching_secrets) == 0:
                    module.fail_json(msg=f"Secret with name '{secret_name}' not found")
                elif len(matching_secrets) > 1:
                    module.fail_json(msg=f"Secret with the same name already exists: {secret_name} \nPlease, set secret_id for update correct secret!")
                
                secret_id = matching_secrets[0].id

            secrets_response = get_secret(iam_token, secret_id)
            secret_status_code = secrets_response.status
            secret_status = STATUS_MAPPING.get(secret_status_code, "UNKNOWN_STATUS")
            if secret_status == 'INACTIVE':
                activate_secret(iam_token, secret_id)
                module.exit_json(changed=True)
            else:
                module.fail_json(msg=f"Activation impossble because secret is {secret_status} now!")
                    
    except Exception as e:
        module.fail_json(msg=str(e))

if __name__ == '__main__':
    main()

