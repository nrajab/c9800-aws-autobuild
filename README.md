# C9800-CL AWS Autobuilder

This class automates the tedious processes involved in configuring an AWS environment when attempting to launch a Catalyst 9800 controller in the cloud. The example script `build_c9800_lab.py` employs the class to build all the constructs necessary for deploying a VPN tunnel between an AWS VPC and an on-premise VPN termination appliance. A VPN tunnel is required in order to extend the LAN from the on-premise environment to the AWS cloud so that the C9800 controller can be seen by the Access Points on the LAN side (a public IP option for the C9800 controller is not supported at this stage). The current release has only the Meraki MX option for the on-premise appliance. Subsequent releases will have the option to choose other VPN termination platforms.


## Installation

This release requires Python 3.6.5. Use the package manager [pip](https://pip.pypa.io/en/stable/) to install the dependencies. The following dependencies are required and can be installed with the corresponding commands.

```bash
pip install boto3
pip install requests
pip install pyyaml
pip install cerberus
```

### boto3

The `boto3` library is the AWS SDK, this is required to interact with the various interfaces on AWS. All the AWS constructs within this script are built using this library.

### requests

There are a few API calls required to retrieve information from each environment and to set certain parameters as well. The `requests` module is used for this purpose.

### pyyaml

This python module is used for parsing YAML files. The `autobuild.py` script uses YAML as a data structure for the config file and requires the `pyyaml` module for retrieving the configuration from the config file.

### cerberus

The configuration file is validated once it is pulled into the `autobuild.py` script. Cerberus is the module that enables the validation. It uses a schema file to compare the config against. The schema file (`build_schema.py`) is included in the repository and must be adhered to as the config file format.

### env_setup.sh

Alternatively, setting up environment can be automated using the environment setup script (`env_setup.sh`) which is included in the repository. The setup script requires 3 parameter inputs, these are, in this order:

1. The AWS region, e.g. us-east-1
2. The AWS access key ID.
3. The AWS secret access key.

The setup can be done as follows.

```bash
./env_setup.sh us-east-1 EYIYWTY8IJS3POWGDSB94 n24m3tgDFIWs34Ed1yQeRWTGd68tjx5id45IOGyj
```

## Usage

### config.yaml

The `config.yaml` file is used for all the parameters that are required for the deployment. All parameters for both sides of the environment are required. That is, all AWS parameters as well as the on-premise parameters, such as Meraki dashboard parameters, are needed for the deployment. The `config.yaml` file must be located in the same directory as the `autobuild.py` script. As mentioned above, the `build_schema.py` file is required for config format validation and must also be located in the same directory as the `autobuild.py` script. The schema file must be included as a parameter when constructing new objects of the `AWSAutoBuild` class.

### aws_autobuild.py

This is the class file and must be imported into the automation script. Once the class is imported it can be used as can be seen in the example script `build_c9800_lab.py`. The usage is as follows:

```bash
python build_c9800_lab.py --configfile config.yaml
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[MIT](https://choosealicense.com/licenses/mit/)
