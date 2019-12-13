import boto3
import logging
import requests
import json
from time import time
from xml.etree import ElementTree
import sys
import yaml
import argparse
from cerberus import Validator

class AWSAutoBuild:
    """docstring for AWSAutoBuild."""

    def __init__(self, build_schema):
        # Create internal class variables
        self.config = {}
        self.logger = logging.getLogger('autobuild_logger')                     # Setup logging resources
        self.ec2_obj = boto3.resource('ec2')                                    # Create resource objects for boto3
        self.ec2_client = boto3.client('ec2')
        self.cf_client = boto3.client('cloudformation')

        # Setup argument parser for config file input and retrieve config file name
        parser = argparse.ArgumentParser()
        parser.add_argument("--configfile", required=True, help="This is the config file parameter, the name is required")
        args = parser.parse_args()
        conf = args.configfile

        # Validate configuration file format
        self.check_config(conf, build_schema)

        # Setup logging for log file and console output
        self.logger = self.set_logging(self.config['project']['base_name'])

    def check_config(self, config_file, build_schema):
        # Load config.yaml for configuration parameters
        with open(config_file, 'r') as ymlfile:
            self.config = yaml.load(ymlfile, Loader=yaml.FullLoader)


        # Set schema template for config file structure validation and validate config input
        schema = eval(open(build_schema, 'r').read())
        v = Validator(schema)
        if not v.validate(self.config, schema):
            print('Config file validation error. Please check the following parameters:')
            print(v.errors)
            sys.exit(1)
        else:
            return

    def set_logging(self, base_name):

        self.logger.setLevel(logging.INFO)

        # Create handlers
        c_handler = logging.StreamHandler()
        f_handler = logging.FileHandler(base_name+'-autobuild.log')
        c_handler.setLevel(logging.INFO)

        # Create formatters and add it to handlers
        c_format = logging.Formatter('%(name)s - %(levelname)s - %(message)s')
        f_format = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        c_handler.setFormatter(c_format)
        f_handler.setFormatter(f_format)

        # Add handlers to the logger
        self.logger.addHandler(c_handler)
        self.logger.addHandler(f_handler)

        return

    def set_meraki_headers(self, api_key, content_type):
        # Set Meraki API headers
        meraki_api_headers = {
          "X-Cisco-Meraki-API-Key": api_key,
          "Content-Type": content_type
        }
        self.logger.info('Meraki API headers have been set')
        return meraki_api_headers

    def get_meraki_org_id(self, meraki_api_headers, meraki_base_uri, meraki_org_name):
        # Retrieve Meraki organisation ID
        meraki_api_url = meraki_base_uri+ '/organizations'
        meraki_api_resp = requests.get(meraki_api_url, headers=meraki_api_headers, verify=False)
        if meraki_api_resp.status_code != 200:
            print(meraki_api_resp.text)
        else:
            meraki_orgs = json.loads(meraki_api_resp.text)
            meraki_org = next(org for org in meraki_orgs if org["name"] == meraki_org_name)
            meraki_org_id = meraki_org['id']
            self.logger.info('Meraki organisation has been retrieved')

        return meraki_org_id

    def get_meraki_ip(self, meraki_api_headers, meraki_base_uri, meraki_org_id, meraki_device_serial):
        # Retrieve Meraki public IP information
        meraki_api_url = meraki_base_uri+ '/organizations/' +meraki_org_id+ '/deviceStatuses'
        meraki_api_resp = requests.get(meraki_api_url, headers=meraki_api_headers, verify=False)
        if meraki_api_resp.status_code != 200:
            print(meraki_api_resp.text)

        meraki_devices = json.loads(meraki_api_resp.text)
        meraki_device = next(device for device in meraki_devices if device["serial"] == meraki_device_serial)
        meraki_public_ip = meraki_device['publicIp']

        self.logger.info('Meraki public IP has been retrieved')
        return meraki_public_ip

    def set_aws_keypair(self, base_name):
        # Creating AWS KeyPair
        key_name = base_name+'-key'
        resp = self.ec2_client.create_key_pair(KeyName=key_name)
        with open(key_name+".pem", "w") as pem_file:
            pem_file.write(resp['KeyMaterial'])

        self.logger.info('AWS key pair for '+ base_name +' has been created')
        return

    def set_aws_vpc(self, cidr_block, base_name):
        # Creating VPC
        vpc = self.ec2_obj.create_vpc(CidrBlock=cidr_block)
        vpc.wait_until_available()

        # Naming VPC
        vpc_name = base_name+'-vpc'
        vpc.create_tags(Tags=[{"Key": "Name", "Value": vpc_name}])

        self.logger.info('VPC '+ vpc_name +' has been created')
        return vpc

    def set_aws_inet_gw(self, vpc):
        # Creating an internet gateway and attach it to VPC
        igw = self.ec2_obj.create_internet_gateway()
        vpc.attach_internet_gateway(InternetGatewayId=igw.id)

        self.logger.info('Internet gateway has been created and attached')
        return igw

    def set_aws_default_route(self, vpc, igw):
        # Creating a route table and a default route
        routetable = vpc.create_route_table()

        route = routetable.create_route(
            DestinationCidrBlock='0.0.0.0/0',
            GatewayId=igw.id
            )
        self.logger.info('Route table and default route has been created')
        return routetable

    def set_aws_subnet(self, vpc, aws_zone, aws_subnet, aws_routetable):
        # Creating subnet and associate it with route table
        subnet = self.ec2_obj.create_subnet(
            AvailabilityZone=aws_zone,
            CidrBlock=aws_subnet,
            VpcId=vpc.id
            )
        aws_routetable.associate_with_subnet(SubnetId=subnet.id)

        self.logger.info('Subnet '+ aws_subnet +' created and associated with route table')
        return subnet

    def set_aws_sec_group(self, base_name, aws_sec_group_descr, vpc, aws_sec_group_protocol, aws_sec_from_port, aws_sec_to_port):
        # Creating a security group and allow traffic inbound rule through the VPC
        aws_sec_group_name = base_name+'-sec-group'
        securitygroup = self.ec2_obj.create_security_group(
            GroupName=aws_sec_group_name,
            Description=aws_sec_group_descr,
            VpcId=vpc.id)
        self.logger.info('Security group '+ aws_sec_group_name +' has been created')

        securitygroup.authorize_ingress(
            CidrIp='0.0.0.0/0',
            IpProtocol=aws_sec_group_protocol,
            FromPort=aws_sec_from_port,
            ToPort=aws_sec_to_port)

        if aws_sec_group_protocol == '-1':
            self.logger.info('Ingress rule for ALL traffic has been applied to the security group')
        else:
            self.logger.info('Ingress rule has been applied to the security group for ports %d to %d' % (AWS_SEC_FROM_PORT, AWS_SEC_TO_PORT))
        return securitygroup

    def set_aws_vpn_gw(self, aws_vpn_gw_type, aws_bgp_asn, dry_run_flag, base_name, vpc):
        # Creating an virtual private gateway and attach it to VPC
        vpgw = self.ec2_client.create_vpn_gateway(
            Type=aws_vpn_gw_type,
            AmazonSideAsn=aws_bgp_asn,
            DryRun=dry_run_flag
        )
        vpgw_id = vpgw['VpnGateway']['VpnGatewayId']

        # Naming virtual private gateway
        vpgw_name = base_name+'-vpgw'
        self.ec2_client.create_tags(
            DryRun=dry_run_flag,
            Resources=[
                vpgw_id,
            ],
            Tags=[
                {
                    'Key': 'Name',
                    'Value': vpgw_name
                },
            ]
        )
        self.logger.info('Virtual private gateway '+ vpgw_name +' has been set up')

        # Attach virtual private gateway to VPC
        self.ec2_client.attach_vpn_gateway(
            VpcId=vpc.id,
            VpnGatewayId=vpgw_id,
            DryRun=dry_run_flag
        )
        self.logger.info('Virtual private gateway is being attached to '+ base_name +'-vpc , please wait .... ')

        # Wait for the virtual private gateway to be attached to VPC before continuing
        vpgw_vpc_state = 'detached'
        while vpgw_vpc_state != 'attached':
            vpgw_detail = self.ec2_client.describe_vpn_gateways(
                VpnGatewayIds=[
                    vpgw_id,
                ],
                DryRun=dry_run_flag
            )
            if vpgw_detail['VpnGateways'][0]['VpcAttachments'][0]['State'] == 'attached':
                vpgw_vpc_state = 'attached'

        self.logger.info('Virtual private gateway ' +vpgw_id+ ' is now attached to VPC '+vpc.id)

        return vpgw_id

    def set_aws_route_propagation(self, aws_vpn_gw_id, aws_routetable):
        # Enable route propagation for virtual gateway
        route_prop = self.ec2_client.enable_vgw_route_propagation(
            GatewayId=aws_vpn_gw_id,
            RouteTableId=aws_routetable.id
        )

        self.logger.info('Route table ' +aws_routetable.id+ ' has been propagated on VPN gateway '+aws_vpn_gw_id)
        return

    def set_aws_customer_gw(self, aws_cust_bgp_asn, meraki_public_ip, tunnel_type, base_name, dry_run_flag):
        # Creating a customer gateway
        cgw = self.ec2_client.create_customer_gateway(
            BgpAsn=aws_cust_bgp_asn,
            PublicIp=meraki_public_ip,
            Type=tunnel_type,
            )
        cgw_id = cgw['CustomerGateway']['CustomerGatewayId']

        # Naming customer gateway
        cgw_name = base_name+'-cgw'
        self.ec2_client.create_tags(
            DryRun=dry_run_flag,
            Resources=[
                cgw_id,
            ],
            Tags=[
                {
                    'Key': 'Name',
                    'Value': cgw_name
                },
            ]
        )
        self.logger.info('Customer gateway ' +cgw_id+ ' has been set up')
        return cgw_id

    def set_aws_vpn_connection(self, aws_cust_gw_id, tunnel_type, aws_vpn_gw_id, dry_run_flag, aws_static_routes_only_flag):
        # Creating VPN connection
        vpn = self.ec2_client.create_vpn_connection(
            CustomerGatewayId=aws_cust_gw_id,
            Type=tunnel_type,
            VpnGatewayId=aws_vpn_gw_id,
            DryRun=dry_run_flag,
            Options={
                'StaticRoutesOnly': aws_static_routes_only_flag
            }
        )
        vpn_id = vpn['VpnConnection']['VpnConnectionId']
        self.logger.info('VPN connection ' +vpn_id+ ' has been built, waiting for availability ...')

        # Adding a monitor to wait for the VPN connection to become available
        vpn_waiter = self.ec2_client.get_waiter('vpn_connection_available')
        vpn_waiter.wait(
            VpnConnectionIds=[
                vpn_id,
            ],
            DryRun=dry_run_flag,
            WaiterConfig={
                'Delay': 30,
                'MaxAttempts': 60
            }
        )
        self.logger.info('VPN connection ' +vpn_id+ ' is available')

        # Saving the VPN connection details to an XML file
        vpn_details = vpn["VpnConnection"]["CustomerGatewayConfiguration"]
        xml_tree_root = ElementTree.fromstring(vpn_details)

        stamp = int(time())
        vpn_details_file_name = 'VPN_connection_details_'+str(stamp)+'.xml'
        tree = ElementTree.ElementTree()
        setting_root = tree._setroot(xml_tree_root)
        tree.write(vpn_details_file_name, encoding='utf-8', xml_declaration=True)
        self.logger.info('VPN connection details file created: '+vpn_details_file_name)

        return vpn_id, xml_tree_root

    def set_aws_remote_subnet_route(self, remote_subnet, aws_vpn_id):
        # Adding a remote site route to the VPN
        vpn_route = self.ec2_client.create_vpn_connection_route(
            DestinationCidrBlock=remote_subnet,
            VpnConnectionId=aws_vpn_id
        )
        self.logger.info('Route to remote subnet '+ remote_subnet +' has been confugured for the AWS VPN')
        return

    def get_aws_vpn_connection_details(self, aws_vpn_xml_tree_root):
        # Retrieve the VPN connection details from the AWS setup
        tunnel_out_ip = aws_vpn_xml_tree_root.find('./ipsec_tunnel/vpn_gateway/tunnel_outside_address/ip_address').text
        tunnel_psk = aws_vpn_xml_tree_root.find('./ipsec_tunnel/ike/pre_shared_key').text
        return tunnel_out_ip, tunnel_psk

    def set_meraki_vpn_connection(self, meraki_org_id, meraki_base_uri, base_name, aws_tunnel_out_ip, aws_tunnel_psk, aws_subnet, meraki_ipsec_policy, meraki_api_headers):
        # Configure the Meraki MX as a tunnel endpoint for the VPN via the API
        meraki_api_url = meraki_base_uri + '/organizations/'+ meraki_org_id +'/thirdPartyVPNPeers'

        meraki_tunnel_endpoint_data = [
          {
            "name": base_name,
            "publicIp": aws_tunnel_out_ip,
            "privateSubnets": [aws_subnet],
            "secret": aws_tunnel_psk,
            "ipsecPoliciesPreset": meraki_ipsec_policy
          }
        ]

        meraki_api_resp = requests.put(meraki_api_url, headers=meraki_api_headers,
                                        data=json.dumps(meraki_tunnel_endpoint_data), verify=False)
        if meraki_api_resp.status_code != 200:
            print(meraki_api_resp.text)
        else:
            self.logger.info('Meraki VPN connection has been configured')

        return

    def launch_c9800_cloudform(self, base_name, cf_template_url, aws_subnet, aws_sec_group, wlc_mgmt_ip, wlc_user, wlc_pass, aws_instance_type):
        # Launching EC2 instance of C9800-CL with CloudFormation template
        stack_name = base_name+'-stack'
        wlc_hostname = base_name+'-wlc'
        response = self.cf_client.create_stack(
            StackName=stack_name,
            TemplateURL=cf_template_url,
            Parameters=[
                  {
                      'ParameterKey': 'Hostname',
                      'ParameterValue': wlc_hostname,
                  },
                  {
                      'ParameterKey': 'KeyName',
                      'ParameterValue': base_name+'-key',
                  },
                  {
                      'ParameterKey': 'ManagementSubnetId',
                      'ParameterValue': aws_subnet.id,
                  },
                  {
                      'ParameterKey': 'MSecurityGroup',
                      'ParameterValue': aws_sec_group.id,
                  },
                  {
                      'ParameterKey': 'MPrivateIP',
                      'ParameterValue': wlc_mgmt_ip,
                  },
                  {
                      'ParameterKey': 'Username',
                      'ParameterValue': wlc_user,
                  },
                  {
                      'ParameterKey': 'PrivilegePwd',
                      'ParameterValue': wlc_pass,
                  },
                  {
                      'ParameterKey': 'ConfirmPwd',
                      'ParameterValue': wlc_pass,
                  },
                  {
                      'ParameterKey': 'C9800InstanceType',
                      'ParameterValue': aws_instance_type,
                  },
            ],
            DisableRollback=False,
            TimeoutInMinutes=2,
            Tags=[
                {
                    'Key': 'name',
                    'Value': wlc_hostname
                },
            ],
        )

        self.logger.info('EC2 instance for c9800-cl has been launched as '+ wlc_hostname +' at '+ wlc_mgmt_ip)
        return
