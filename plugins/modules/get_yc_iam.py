#!/usr/bin/python

import json
import sys
import os
from time import time

from ansible.module_utils.basic import AnsibleModule

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
from grpc import RpcError

from yandexcloud import SDK
from yandex.cloud.iam.v1.iam_token_service_pb2_grpc import IamTokenServiceStub
from yandex.cloud.iam.v1.iam_token_service_pb2 import CreateIamTokenRequest

def get_iam_token_from_jwt(sa_key_file):
    try:
        with open(sa_key_file, 'r') as file:
            private_key_data = json.load(file)
    except Exception as e:
        raise Exception(f"Ошибка чтения файла ключей: {str(e)}")

    required_fields = ['id', 'service_account_id', 'private_key']
    for field in required_fields:
        if field not in private_key_data:
            raise Exception(f"Отсутствует обязательное поле {field} в файле ключей")

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
        raise Exception(f"Ошибка формирования JWT: {str(e)}")

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

def get_iam_token_from_oauth(oauth_token):
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

def run_module():
    module_args = dict(
        auth_type=dict(type='str', required=True, choices=['jwt', 'oauth']),
        auth_value=dict(type='str', required=True)
    )

    result = dict(
        changed=False,
        original_message='',
        iam_token=''
    )

    module = AnsibleModule(
        argument_spec=module_args,
        supports_check_mode=True
    )

    auth_type = module.params['auth_type']
    auth_value = module.params['auth_value']

    try:
        if auth_type == 'jwt':
            iam_token = get_iam_token_from_jwt(auth_value)
        elif auth_type == 'oauth':
            iam_token = get_iam_token_from_oauth(auth_value)
        else:
            module.fail_json(msg="Неподдерживаемый тип аутентификации. Используйте 'jwt' или 'oauth'.")
        
        result['changed'] = True
        result['original_message'] = f"Получен IAM токен с использованием {auth_type}"
        result['iam_token'] = iam_token
    except Exception as e:
        module.fail_json(msg=str(e))

    module.exit_json(**result)

def main():
    run_module()

if __name__ == '__main__':
    main()
