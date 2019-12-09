# C9800-CL AWS Autobuilder

This script automates the tedious process of configuring an AWS environment in order to launch a Catalyst 9800 controller in the cloud. The script builds all the constructs necessary for deploying a VPN tunnel between an AWS VPC and an on-premise VPN termination appliance. A VPN tunnel is required in order to extend the LAN from the on-premise environment to the AWS cloud so that the C9800 controller can be seen by the Access Points on the LAN side (a public IP option for the C9800 controller is not supported at this stage). The current release has only the Meraki MX option for the on-premise appliance. Subsequent releases will have the option to choose other VPN termination platforms.


## Installation

This release requires Python 3.6.5. Use the package manager [pip](https://pip.pypa.io/en/stable/) to install the dependencies. The following dependencies are required and can be installed with the corresponding commands.

```bash
pip install boto3
pip install requests
```

Alternatively, the environment setup can be automated using the environment setup script (env_setup.sh) which is included in the repository. The setup script requires 3 parameter inputs, these are, in this order:

1. The AWS region, e.g. us-east-1
2. The AWS access key ID.
3. The AWS secret access key.

The setup can be done as follows.

```bash
./env_setup.sh us-east-1 EYIYWTY8IJS3POWGDSB94 n24m3tgDFIWs34Ed1yQeRWTGd68tjx5id45IOGyj
```

## Usage

### config.py

The `config.py` file is used for all the paramaters that are required for the deployment. All parameters for both sides of the environment are required. That is, all AWS parameters as well as the on-premise parameters, such as Meraki dashboard parameters are needed for the deployment. The `config.py` file must be located in the same directory as the `autobuild.py` script.

### autobuild.py

```bash
python autobuild.py
```

## Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

Please make sure to update tests as appropriate.

## License
[MIT](https://choosealicense.com/licenses/mit/)
