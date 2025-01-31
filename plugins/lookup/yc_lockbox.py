#!/usr/bin/python
# -*- coding: utf-8 -*-
from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = '''
lookup: yc_lockbox
author: "Nikolay Krasnov @krang404"
short_description: Fetch secret from Yandex Cloud Lockbox using service account key or OAuth token
description:
  - This lookup fetches a secret from Yandex Cloud Lockbox using a service account key file or OAuth token.
  - The token_type can be 'iam', 'oauth', or 'sa'. Default is 'sa'.
options:
  _terms:
    description:
      - secret_id: The ID of the secret in Yandex Cloud Lockbox.
      - key: The key of the secret entry.
      - token_type: The type of token used for authentication ('iam', 'oauth', or 'sa'). Optional.
    required: True
    type: list
notes:
  - Ensure that you have the necessary Yandex Cloud SDK installed.
  - Ensure that the service account key file or OAuth token is valid and has the necessary permissions.
  - Ensuer that you put path to the service account key file in YC_SA_KEY_FILE_PATH.
requirements:
  - yandexcloud
  - PyJWT
  - grpcio
'''

EXAMPLES = '''
- name: Fetch secret from Yandex Cloud Lockbox using service account key
  debug:
    msg: "{{ lookup('yc_lockbox', 'secret_id', 'key') }}"

- name: Fetch secret from Yandex Cloud Lockbox using OAuth token
  debug:
    msg: "{{ lookup('yc_lockbox', 'secret_id', 'key', 'oauth') }}"
'''

RETURN = '''
_list:
  description: The value of the secret entry from Yandex Cloud Lockbox.
  type: list
  elements: str
  sample: ['your_secret_value']
'''

import os
import json
import sys
from time import time
from ansible.plugins.lookup import LookupBase
from ansible.errors import AnsibleError

def check_module_installed(module_name):
    import importlib.util
    if importlib.util.find_spec(module_name) is None:
        raise ImportError(f"The module '{module_name}' is not installed. Install it using 'pip install {module_name}'")

try:
    check_module_installed('jwt') 
    check_module_installed('cryptography')
    check_module_installed('yandexcloud')
except ImportError as e:
    print(e)
    sys.exit(1)

import jwt

from yandexcloud import SDK
from yandex.cloud.lockbox.v1.payload_service_pb2 import GetPayloadRequest
from yandex.cloud.lockbox.v1.payload_service_pb2_grpc import PayloadServiceStub
from yandex.cloud.iam.v1.iam_token_service_pb2_grpc import IamTokenServiceStub
from yandex.cloud.iam.v1.iam_token_service_pb2 import CreateIamTokenRequest

class LookupModule(LookupBase):
    
    def get_sa_key(self):
        file_path = os.getenv('YC_SA_KEY_FILE_PATH')

        if file_path is None:
            raise ValueError("The environment variable 'YC_SA_KEY_FILE_PATH' is not set")

        try:
            with open(file_path, 'r') as file:
                file_content = file.read()
        except FileNotFoundError:
            raise FileNotFoundError(f"The file at path '{file_path}' was not found")

        try:
            sa_key_data = json.loads(file_content)
        except json.JSONDecodeError:
            raise ValueError("Invalid file format: unable to parse JSON")

        required_keys = {"id", "service_account_id", "private_key"}
        if not required_keys.issubset(sa_key_data):
            raise ValueError("Invalid file format: missing required keys 'id', 'service_account_id', and 'private_key'")

        return sa_key_data
    
    def get_iam_token(self):
        sa_key = self.get_sa_key()
        service_account_id = sa_key['service_account_id']
        private_key_id = sa_key['id']
        private_key = sa_key['private_key']

        now = int(time())
        payload = {
                'aud': 'https://iam.api.cloud.yandex.net/iam/v1/tokens',
                'iss': service_account_id,
                'iat': now,
                'exp': now + 3600
            }

        jwt_token = jwt.encode(payload, private_key, algorithm='PS256', headers={'kid': private_key_id})

        sdk = SDK(service_account_key=sa_key)
        iam_client = sdk.client(IamTokenServiceStub)

        operation_create_iam_token = iam_client.Create(CreateIamTokenRequest(jwt=jwt_token))
        iam_token = operation_create_iam_token.iam_token

        return iam_token
    

    def run(self, terms, variables=None, **kwargs):
        if len(terms) < 2 or len(terms) > 3:
            raise AnsibleError('This lookup module expects two or three arguments: secret_id, key, and optionally token_type')

        secret_id = terms[0]
        key = terms[1]
        token_type = terms[2] if len(terms) == 3 else 'iam'
            
        if token_type == 'iam':
            iam_token = os.getenv('YC_IAM_TOKEN')
            if iam_token is None or iam_token.strip() == "":
                iam_token = self.get_iam_token()
            sdk = SDK(iam_token=iam_token)
        elif token_type == 'oauth':
            oauth_token = os.getenv('YC_OAUTH_TOKEN')
            sdk = SDK(token=oauth_token)
        elif token_type == 'sa':
            sa = self.get_sa_key()
            sdk = SDK(service_account_key=sa)
        else:
            raise AnsibleError('Term token_type must be "iam", "oauth" or "sa"!\nBut no need to set it if you have YC_SA_KEY_FILE_PATH in os environment')
        
        lockbox_client = sdk.client(PayloadServiceStub)

        request = lockbox_client.Get(GetPayloadRequest(secret_id=secret_id))

        for entry in request.entries:
            if entry.key == key:
                return [entry.text_value]

        raise AnsibleError(f'Key {key} not found in secret {secret_id}')
    
