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


import requests
import yaml
from ansible.module_utils.basic import AnsibleModule

def create_secret(iam_token, folder_id, secret_name, secret_description, version_payload_entries, delete_protection):
    url = "https://lockbox.api.cloud.yandex.net/lockbox/v1/secrets"
    headers = {"Authorization": f"Bearer {iam_token}", "Content-Type": "application/json"}
    payload = {
        "folderId": folder_id,
        "name": secret_name,
        "description": secret_description,
        "versionPayloadEntries": version_payload_entries,
        "deletionProtection": delete_protection
    }

    response = requests.post(url, headers=headers, json=payload)
    response.raise_for_status()
    return response.json()

def list_secrets(iam_token, folder_id):
    url = f"https://lockbox.api.cloud.yandex.net/lockbox/v1/secrets?folderId={folder_id}"
    headers = {"Authorization": f"Bearer {iam_token}"}
    
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()

def get_secret(iam_token, secret_id):
    url = f"https://lockbox.api.cloud.yandex.net/lockbox/v1/secrets/{secret_id}"
    headers = {"Authorization": f"Bearer {iam_token}"}
    
    response = requests.get(url, headers=headers)
    response.raise_for_status()
    return response.json()

def delete_secret(iam_token, secret_id):
    url = f"https://lockbox.api.cloud.yandex.net/lockbox/v1/secrets/{secret_id}"
    headers = {"Authorization": f"Bearer {iam_token}"}
    
    response = requests.delete(url, headers=headers)
    if response.status_code == 400:
        error_message = response.json().get('message', '')
        if 'deletion_protection' in error_message:
            raise Exception(f"Secret with id '{secret_id}' is protected from deletion. Update 'deletion_protection' field to delete the secret.")
    response.raise_for_status()
    return response.json()

def update_secret(iam_token, secret_id, secret_description, version_payload_entries, current_version_id):
    url = f"https://lockbox.api.cloud.yandex.net/lockbox/v1/secrets/{secret_id}:addVersion"
    headers = {"Authorization": f"Bearer {iam_token}", "Content-Type": "application/json"}
    payload = {
        "description": secret_description,
        "payloadEntries": version_payload_entries,
        "baseVersionId": current_version_id
    }

    response = requests.post(url, headers=headers, json=payload)
    response.raise_for_status()
    return response.json()

def activate_secret(iam_token, secret_id):
    url = f"https://lockbox.api.cloud.yandex.net/lockbox/v1/secrets/{secret_id}:activate"
    headers = {"Authorization": f"Bearer {iam_token}", "Content-Type": "application/json"}

    response = requests.post(url, headers=headers)
    response.raise_for_status()
    return response.json()

def deactivate_secret(iam_token, secret_id):
    url = f"https://lockbox.api.cloud.yandex.net/lockbox/v1/secrets/{secret_id}:deactivate"
    headers = {"Authorization": f"Bearer {iam_token}", "Content-Type": "application/json"}

    response = requests.post(url, headers=headers)
    response.raise_for_status()
    return response.json()

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
    )

    module = AnsibleModule(
        argument_spec=argument_spec,
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

    try:
        combined_secret_data = text_payload_entries.copy()

        if secret_data_file:
            secret_data_from_file = load_secret_data_file(secret_data_file)
            for key in secret_data_from_file:
                if key in combined_secret_data:
                    module.fail_json(msg=f"Duplicate key '{key}' found in both text_payload_entries and secret_data_file.")
            combined_secret_data.update(secret_data_from_file)

        version_payload_entries = [{'key': key, 'textValue': value} for key, value in combined_secret_data.items()]
        if len(version_payload_entries) > 32:
            raise ValueError("The number of keys in version_payload_entries exceeds the limit of 32.")

        if state == 'present':
            if not secret_id:
                secrets_response = list_secrets(iam_token, folder_id)
                if 'secrets' in secrets_response:
                    secrets = secrets_response['secrets']
                    for secret in secrets:
                        if secret['name'] == secret_name:
                            module.fail_json(msg=f"Secret with the same name already exists: {secret_name}")
            
            response = create_secret(iam_token, folder_id, secret_name, secret_description, version_payload_entries, delete_protection)
            module.exit_json(changed=True, id=response['id'])
        
        elif state == 'absent':
            if not secret_id:
                secrets_response = list_secrets(iam_token, folder_id)
                if 'secrets' not in secrets_response:
                    module.exit_json(changed=False)

                matching_secrets = [secret for secret in secrets_response['secrets'] if secret['name'] == secret_name]
                if len(matching_secrets) == 0:
                    module.exit_json(changed=False)
                elif len(matching_secrets) > 1:
                    module.fail_json(msg=f"Multiple secrets found with name: {secret_name}")
                secret_id = matching_secrets[0]['id']
            
            delete_secret(iam_token, secret_id)
            module.exit_json(changed=True)

        elif state == 'update':
            if not secret_id:
                secrets_response = list_secrets(iam_token, folder_id)
                if 'secrets' not in secrets_response:
                    module.fail_json(msg="No secrets for update")
                elif 'secrets' in secrets_response:
                    secrets = secrets_response['secrets']
                    for secret in secrets:
                        if secret['name'] == secret_name:
                            module.fail_json(msg=f"Secret with the same name already exists: {secret_name} \nPlease, set secret_id for update correct secret!")

                matching_secrets = [secret for secret in secrets_response['secrets'] if secret['name'] == secret_name]
                secret_id = matching_secrets[0]['id']
                current_version_id = matching_secrets[0]['currentVersion']['id']
            elif secret_id:
                secrets_response = get_secret(iam_token, secret_id)
                current_version_id = secrets_response['currentVersion']['id']

            update_secret(iam_token, secret_id, secret_description, version_payload_entries, current_version_id)
            module.exit_json(changed=True)

        elif state == 'deactivate':
            if not secret_id:
                secrets_response = list_secrets(iam_token, folder_id)
                if 'secrets' not in secrets_response:
                    module.fail_json(msg="No secrets for deactivate")
                elif 'secrets' in secrets_response:
                    secrets = secrets_response['secrets']
                    for secret in secrets:
                        if secret['name'] == secret_name:
                            module.fail_json(msg=f"Secret with the same name already exists: {secret_name} \nPlease, set secret_id for deactivate correct secret!")

                matching_secrets = [secret for secret in secrets_response['secrets'] if secret['name'] == secret_name]
                secret_id = matching_secrets[0]['id']

            secrets_response = get_secret(iam_token, secret_id)
            secret_status = secrets_response['status']
            if secret_status == 'ACTIVE':
                deactivate_secret(iam_token, secret_id)
                module.exit_json(changed=True)
            else:
                module.fail_json(msg=f"Deactivation impossble because secret is {secret_status} now!")
                
        elif state == 'activate':
            if not secret_id:
                secrets_response = list_secrets(iam_token, folder_id)
                if 'secrets' not in secrets_response:
                    module.fail_json(msg="No secrets for deactivate")
                elif 'secrets' in secrets_response:
                    secrets = secrets_response['secrets']
                    for secret in secrets:
                        if secret['name'] == secret_name:
                            module.fail_json(msg=f"Secret with the same name already exists: {secret_name} \nPlease, set secret_id for activate correct secret!")

                matching_secrets = [secret for secret in secrets_response['secrets'] if secret['name'] == secret_name]
                secret_id = matching_secrets[0]['id']

            secrets_response = get_secret(iam_token, secret_id)
            secret_status = secrets_response['status']
            if secret_status == 'INACTIVE':
                activate_secret(iam_token, secret_id)
                module.exit_json(changed=True)
            else:
                module.fail_json(msg=f"Activation impossble because secret is {secret_status} now!")
                    
    except requests.exceptions.RequestException as e:
        module.fail_json(msg=str(e))
    except ValueError as e:
        module.fail_json(msg=str(e))

if __name__ == '__main__':
    main()

