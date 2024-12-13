#!/usr/bin/python

from __future__ import (absolute_import, division, print_function)
__metaclass__ = type

DOCUMENTATION = '''
lookup: yc_iam_token
author: "Nikolay Krasnov @krang404"
short_description: Get IAM token from Yandex Cloud using JWT or OAuth
description:
  - This lookup fetches an IAM token from Yandex Cloud using a service account key file (JWT) or OAuth token.
options:
  _terms:
    description: Type of authentication and value (JWT file path or OAuth token).
    required: True
    type: list
notes:
  - Ensure that you have the necessary Yandex Cloud SDK installed.
  - Ensure that the service account key file or OAuth token is valid and has the necessary permissions.
requirements:
  - yandexcloud
  - PyJWT
  - grpcio
'''

EXAMPLES = '''
- name: Get IAM token using JWT
  debug:
    msg: "{{ lookup('yc_iam_token', 'jwt', '/path/to/sa_key.json') }}"

- name: Get IAM token using OAuth
  debug:
    msg: "{{ lookup('yc_iam_token', 'oauth', 'your_oauth_token') }}"
'''

RETURN = '''
  _list:
    description: The IAM token from Yandex Cloud.
    type: list
    elements: str
    sample: ['y0_AgAAAAA...']
'''

import json
import sys
import os
from time import time
from grpc import RpcError

from ansible.plugins.lookup import LookupBase
from ansible.errors import AnsibleError

# Проверка установленных модулей
def check_module_installed(module_name):
    import importlib.util
    if importlib.util.find_spec(module_name) is None:
        raise ImportError(f"Модуль '{module_name}' не установлен. Установите его с помощью 'pip install {module_name}'")

# Проверяем наличие необходимых модулей
try:
    check_module_installed('jwt')  # PyJWT
    check_module_installed('cryptography')
    check_module_installed('yandexcloud')
except ImportError as e:
    print(e)
    sys.exit(1)

import jwt

from yandexcloud import SDK
from yandex.cloud.iam.v1.iam_token_service_pb2_grpc import IamTokenServiceStub
from yandex.cloud.iam.v1.iam_token_service_pb2 import CreateIamTokenRequest



class LookupModule(LookupBase):

    def get_iam_token_from_jwt(self, sa_key_file):
        try:
            with open(sa_key_file, 'r') as file:
                private_key_data = json.load(file)
        except Exception as e:
            raise AnsibleError(f"Ошибка чтения файла ключей: {str(e)}")

        required_fields = ['id', 'service_account_id', 'private_key']
        for field in required_fields:
            if field not in private_key_data:
                raise AnsibleError(f"Отсутствует обязательное поле {field} в файле ключей")

        private_key_id = private_key_data['id']
        service_account_id = private_key_data['service_account_id']
        private_key = private_key_data['private_key']

        now = int(time())
        payload = {
            'aud': 'https://iam.api.cloud.yandex.net/iam/v1/tokens',
            'iss': service_account_id,
            'iat': now,
            'exp': now + 3600
        }

        try:
            jwt_token = jwt.encode(payload, private_key, algorithm='PS256', headers={'kid': private_key_id})
        except Exception as e:
            raise AnsibleError(f"Ошибка формирования JWT: {str(e)}")

        try:
            sdk = SDK(service_account_key=private_key_data)
            iam_client = sdk.client(IamTokenServiceStub)

            operation_create_iam_token = iam_client.Create(CreateIamTokenRequest(jwt=jwt_token))
            iam_token = operation_create_iam_token.iam_token

            return iam_token
        
        except ValueError as e:
            print(f"Ошибка валидации данных: {e}")
            raise
        except FileNotFoundError as e:
            print(f"Ошибка чтения файла: {e}")
            raise
        except RpcError as e:
            print(f"Ошибка RPC: {e}")
            raise
        except Exception as e:
            print(f"Неизвестная ошибка: {e}")
            raise
        
    def get_iam_token_from_oauth(self, oauth_token):
        try:
            oauth_token = os.getenv('YC_OAUTH_TOKEN')
            sdk = SDK(token=oauth_token)
            iam_client = sdk.client(IamTokenServiceStub)

            operation_create_iam_token = iam_client.Create(CreateIamTokenRequest(yandex_passport_oauth_token=oauth_token))
            iam_token = operation_create_iam_token.iam_token

            return iam_token
        
        except ValueError as e:
            print(f"Ошибка валидации данных: {e}")
            raise
        except FileNotFoundError as e:
            print(f"Ошибка чтения файла: {e}")
            raise
        except RpcError as e:
            print(f"Ошибка RPC: {e}")
            raise
        except Exception as e:
            print(f"Неизвестная ошибка: {e}")
            raise

    def run(self, terms, variables=None, **kwargs):
        if len(terms) < 2:
            raise AnsibleError("Требуется указать тип аутентификации и значение (JWT файл или OAuth токен)")

        auth_type = terms[0]
        auth_value = terms[1]

        try:
            if auth_type == 'jwt':
                iam_token = self.get_iam_token_from_jwt(auth_value)
            elif auth_type == 'oauth':
                iam_token = self.get_iam_token_from_oauth(auth_value)
            else:
                raise AnsibleError("Неподдерживаемый тип аутентификации. Используйте 'jwt' или 'oauth'.")
            return [iam_token]
        except Exception as e:
            raise AnsibleError(f"Ошибка получения IAM токена: {str(e)}")
