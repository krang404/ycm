# Yandex Cloud Modules (YCM)

**YCM** is a collection of Ansible modules designed to manage Yandex Cloud resources for tasks not covered by the Terraform provider. 

## Features

Currently, modules for working with **Lockbox** and **IAM** are implemented, and new modules are added as they are developed.  

### Key Features:
- **Secret creation**: Easily create new secrets in Yandex Lockbox with specified parameters.  
- **Secret updates**: Add new versions to existing secrets with updated data.  
- **Secret deletion**: Delete secrets from Yandex Lockbox.  
- **Activate/Deactivate secrets**: Change the status of secrets to active or inactive as needed.  
- **Retrieve IAM token**: Use the `yc_iam_token` lookup plugin to dynamically retrieve an IAM token using a service account key file, simplifying authentication for Yandex Cloud API operations.  

---  

Let me know if you need further refinements!

## Requirements

- Python 3.10 or higher.
- Ansible 2.9 or higher.
- `yandexcloud` Python SDK.

## Installation

1. **Clone the Repository**:

   ```bash
   git clone https://github.com/krang404/ycm.git
   ```

2. **Install Dependencies**:

   ```bash
   pip install -r requirements.txt
   ```

## Usage

To use the Yandex Cloud Module in your Ansible playbooks, include it as a custom module.

### Example Playbook

```yaml
- name: Manage Yandex Cloud Secrets
  hosts: localhost
  tasks:
    - name: Create a new secret
      ycm:
        iam_token: "{{ lookup('yc_iam_token', 'jwt', '/path/to/sa_key.json') }}"
        folder_id: "your-folder-id"
        secret_name: "example_secret"
        secret_description: "An example secret"
        text_payload_entries:
          key1: "value1"
          key2: "value2"
        state: present
```

## Lookup Plugins

YCM includes lookup plugins to fetch IAM tokens and secret values from Yandex Cloud.

### `yc_iam_token` Lookup Plugin

This plugin retrieves an IAM token using a service account key file.

**Usage Example**:

```yaml
- name: Obtain IAM Token via SA-key
  debug:
    msg: "{{ lookup('yc_iam_token', 'jwt', '/path/to/sa_key.json') }}"

- name: Obtain IAM Token via OAuth

  debug:
    msg: "{{ lookup('yc_iam_token', 'oauth', 'your_oauth_token') }}"
```

### `yc_lockbox` Lookup Plugin

This plugin fetches secret values from Yandex Lockbox.

**Usage Example**:

```yaml
- name: Retrieve secret value
  debug:
    msg: "{{ lookup('yc_lockbox', 'secret-id', iam_token) }}"
```

## Error Handling

The module includes error handling to manage exceptions that may occur during API interactions. If an error is encountered, the module will fail gracefully, providing an appropriate error message.

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your changes. Ensure that your code adheres to the existing style and includes appropriate tests.

## License

This project is licensed under the Apache License 2.0. See the [LICENSE](https://github.com/krang404/ycm/blob/main/LICENSE) file for details.

## Acknowledgments

This project utilizes the [Yandex Cloud SDK for Python](https://github.com/yandex-cloud/python-sdk) and is inspired by best practices in Ansible module development.

For more information, visit the [ycm GitHub repository](https://github.com/krang404/ycm). 