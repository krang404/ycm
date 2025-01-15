# ycm

**ycm** is a collection of Ansible modules designed to interact with Yandex Cloud services, enabling automation of various cloud resource management tasks.

## Features

- **Secret Management**: Create, update, activate, deactivate, and delete secrets in Yandex Lockbox.
- **Payload Handling**: Support for managing secret payloads through direct dictionary inputs or YAML files.
- **State Management**: Ensure secrets are in the desired state (`present`, `absent`, `update`, `deactivate`, `activate`).
- **Idempotency**: Designed to prevent unnecessary changes if the desired state is already achieved.

## Requirements

- Python 3.6 or higher
- Ansible 2.9 or higher
- `yandexcloud` Python SDK
- `PyYAML` library

## Installation

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/krang404/ycm.git
   ```

2. **Install Dependencies**:

   ```bash
   pip install yandexcloud pyyaml
   ```

3. **Configure Ansible**:

   Ensure that the `ycm` modules are in your Ansible module search path or specify the path in your playbooks.

## Usage

Here's an example of how to use the `ycm` module in an Ansible playbook to create a secret in Yandex Lockbox:

```yaml
- name: Manage Yandex Lockbox Secret
  hosts: localhost
  tasks:
    - name: Create a new secret
      ycm:
        iam_token: "{{ iam_token }}"
        folder_id: "{{ folder_id }}"
        secret_name: "my_secret"
        secret_description: "This is a test secret"
        text_payload_entries:
          key1: "value1"
          key2: "value2"
        state: present
```

**Parameters**:

- `iam_token` (required): IAM token for authenticating with Yandex Cloud.
- `folder_id` (required for creating secrets): ID of the folder where the secret will reside.
- `secret_name` (required): Name of the secret.
- `secret_description` (optional): Description of the secret.
- `text_payload_entries` (optional): Dictionary of key-value pairs to store in the secret.
- `secret_data_file` (optional): Path to a YAML file containing secret data.
- `state` (optional): Desired state of the secret. Choices are `present`, `absent`, `update`, `deactivate`, `activate`. Default is `present`.
- `delete_protection` (optional): Boolean to enable or disable deletion protection. Default is `true`.

## Error Handling

The module includes error handling to manage exceptions that may occur during API interactions. If an error is encountered, the module will fail gracefully, providing an appropriate error message.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your changes. Ensure that your code adheres to the existing style and includes appropriate tests.

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](https://github.com/krang404/ycm/blob/main/LICENSE) file for details.

## Acknowledgments

This project utilizes the [Yandex Cloud SDK for Python](https://github.com/yandex-cloud/python-sdk) and is inspired by best practices in Ansible module development.

For more information, visit the [ycm GitHub repository](https://github.com/krang404/ycm). 