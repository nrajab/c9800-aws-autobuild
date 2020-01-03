import boto3
import logging
import requests
import json
from xml.etree import ElementTree
import sys
import yaml
import argparse
from cerberus import Validator

class AWSAutoBuild:

    def __init__(self, build_schema):
        # Create internal class variables
        self.config = {}
        self.logger = {}                                                        # Setup logging resources
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
        logger = logging.getLogger('autobuild_logger')
        logger.setLevel(logging.INFO)

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
        logger.addHandler(c_handler)
        logger.addHandler(f_handler)

        return logger

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

    def del_aws_keypair(self, base_name):
        self.ec2_client.delete_key_pair(
            KeyName=base_name+'-key',
        )

        self.logger.info('AWS key pair for '+ base_name +' has been deleted')
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

    def del_aws_vpc(self, base_name):
        vpc = self.ec2_client.describe_vpcs(
            Filters = [
                { 'Name': 'tag:Name', 'Values': [base_name+'-vpc']}
            ]
        )
        vpc_id = vpc['Vpcs'][0]['VpcId']

        self.ec2_client.delete_vpc(
            VpcId=vpc_id,
        )

        self.logger.info('AWS VPC '+ vpc_id +' has been deleted')
        return

    def set_aws_inet_gw(self, vpc, base_name):
        # Creating an internet gateway and attach it to VPC
        igw = self.ec2_obj.create_internet_gateway()
        igw_name = base_name+'-igw'
        igw.create_tags(Tags=[{"Key": "Name", "Value": igw_name}])
        vpc.attach_internet_gateway(InternetGatewayId=igw.id)

        self.logger.info('Internet gateway has been created and attached')
        return igw

    def del_aws_inet_gw(self, base_name):
        igw = self.ec2_client.describe_internet_gateways(
            Filters = [
                { 'Name': 'tag:Name', 'Values': [base_name+'-igw']}
            ]
        )
        igw_id = igw['InternetGateways'][0]['InternetGatewayId']
        if igw['InternetGateways'][0]['Attachments'] == []:
            self.ec2_client.delete_internet_gateway(
                InternetGatewayId=igw_id,
            )
            self.logger.info('Internet gateway ' +igw_id+ ' has been deleted')
            return
        else:
            igw_vpc_state = igw['InternetGateways'][0]['Attachments'][0]['State']
            vpc_id = igw['InternetGateways'][0]['Attachments'][0]['VpcId']
            igw_attach = igw['InternetGateways'][0]['Attachments']

            self.ec2_client.detach_internet_gateway(
                InternetGatewayId=igw_id,
                VpcId=vpc_id
            )

            while igw_attach != []:
                igw = self.ec2_client.describe_internet_gateways(
                    Filters = [
                        { 'Name': 'tag:Name', 'Values': [base_name+'-igw']}
                    ]
                )
                igw_attach = igw['InternetGateways'][0]['Attachments']
                if igw_vpc_state == []:
                    self.logger.info('Internet gateway ' +igw_id+ ' is now detached from VPC '+vpc_id)

            self.ec2_client.delete_internet_gateway(
                InternetGatewayId=igw_id,
            )
            self.logger.info('Internet gateway ' +igw_id+ ' has been deleted')
            return

    def set_aws_default_route(self, vpc, igw, base_name):
        # Creating a route table and a default route
        routetable = vpc.create_route_table()
        routetable.create_tags(Tags=[{"Key": "Name", "Value": base_name+'-rtbl'}])

        route = routetable.create_route(
            DestinationCidrBlock='0.0.0.0/0',
            GatewayId=igw.id
            )
        self.logger.info('Route table and default route has been created')
        return routetable

    def del_aws_route_table(self, base_name):
        route_table = self.ec2_client.describe_route_tables(
            Filters = [
                { 'Name': 'tag:Name', 'Values': [base_name+'-rtbl']}
            ]
        )
        rt_table_id = route_table['RouteTables'][0]['RouteTableId']

        self.ec2_client.delete_route_table(
            RouteTableId=rt_table_id,
        )
        self.logger.info('Route table ' +rt_table_id+ ' has been deleted')
        return

    def set_aws_subnet(self, vpc, aws_zone, aws_subnet, aws_routetable, base_name):
        # Creating subnet and associate it with route table
        subnet = self.ec2_obj.create_subnet(
            AvailabilityZone=aws_zone,
            CidrBlock=aws_subnet,
            VpcId=vpc.id
            )
        subnet.create_tags(Tags=[{"Key": "Name", "Value": base_name+'-subnet'}])
        aws_routetable.associate_with_subnet(SubnetId=subnet.id)

        self.logger.info('Subnet '+ aws_subnet +' created and associated with route table')
        return subnet

    def del_aws_subnet(self, base_name):
        subnet = self.ec2_client.describe_subnets(
            Filters = [
                { 'Name': 'tag:Name', 'Values': [base_name+'-subnet']}
            ]
        )
        subnet_id = subnet['Subnets'][0]['SubnetId']

        self.ec2_client.delete_subnet(
            SubnetId=subnet_id,
        )
        self.logger.info('Subnet ' +subnet_id+ ' has been deleted')
        return

    def del_aws_net_acl(self, base_name):
        sec_group = self.ec2_client.describe_security_groups(
            Filters = [
                { 'Name': 'tag:Name', 'Values': [base_name+'-sec-group']}
            ]
        )
        sec_group_id = sec_group['SecurityGroups'][0]['GroupId']

        self.ec2_client.delete_security_group(
            GroupId=sec_group_id,
        )
        self.logger.info('Security group ' +sec_group_id+ ' has been deleted')
        return

    def set_aws_sec_group(self, base_name, aws_sec_group_descr, vpc, aws_sec_group_protocol, aws_sec_from_port, aws_sec_to_port):
        # Creating a security group and allow traffic inbound rule through the VPC
        securitygroup = self.ec2_obj.create_security_group(
            GroupName=base_name,
            Description=aws_sec_group_descr,
            VpcId=vpc.id)
        securitygroup.create_tags(Tags=[{"Key": "Name", "Value": base_name+'-sec-group'}])
        self.logger.info('Security group '+ securitygroup.id +' has been created')

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

    def del_aws_sec_group(self, base_name):
        sec_group = self.ec2_client.describe_security_groups(
            Filters = [
                { 'Name': 'tag:Name', 'Values': [base_name+'-sec-group']}
            ]
        )
        sec_group_id = sec_group['SecurityGroups'][0]['GroupId']

        self.ec2_client.delete_security_group(
            GroupId=sec_group_id,
        )
        self.logger.info('Security group ' +sec_group_id+ ' has been deleted')
        return

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
        self.logger.info('Virtual private gateway '+ vpgw_name +' is being attached to '+ base_name +'-vpc , please wait .... ')

        # Wait for the virtual private gateway to be attached to VPC before continuing
        vpgw_vpc_state = 'detached'
        while vpgw_vpc_state != 'attached':
            vpgw_detail = self.ec2_client.describe_vpn_gateways(
                VpnGatewayIds=[
                    vpgw_id,
                ],
            )
            if vpgw_detail['VpnGateways'][0]['VpcAttachments'][0]['State'] == 'attached':
                vpgw_vpc_state = 'attached'

        self.logger.info('Virtual private gateway ' +vpgw_id+ ' is now attached to VPC '+vpc.id)

        return vpgw_id

    def del_aws_vpn_gw(self, base_name):
        vpgw = self.ec2_client.describe_vpn_gateways(
            Filters = [
                { 'Name': 'tag:Name', 'Values': [base_name+'-vpgw']}
            ]
        )
        vpgw_id = vpgw['VpnGateways'][0]['VpnGatewayId']
        vpgw_vpc_state = vpgw['VpnGateways'][0]['VpcAttachments'][0]['State']
        vpc_id = vpgw['VpnGateways'][0]['VpcAttachments'][0]['VpcId']

        self.ec2_client.detach_vpn_gateway(
            VpcId=vpc_id,
            VpnGatewayId=vpgw_id,
        )

        while vpgw_vpc_state != 'detached':
            vpgw_detail = self.ec2_client.describe_vpn_gateways(
                VpnGatewayIds=[
                    vpgw_id,
                ],
            )
            vpgw_vpc_state = vpgw_detail['VpnGateways'][0]['VpcAttachments'][0]['State']
            if vpgw_vpc_state == 'detached':
                self.logger.info('Virtual private gateway ' +vpgw_id+ ' is now detached from VPC '+vpc_id)

        self.ec2_client.delete_vpn_gateway(
            VpnGatewayId=vpgw_id,
        )
        self.logger.info('Virtual private gateway ' +vpgw_id+ ' has been deleted')
        return

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

    def del_aws_customer_gw(self, base_name):
        cgw = self.ec2_client.describe_customer_gateways(
            Filters = [
                { 'Name': 'tag:Name', 'Values': [base_name+'-cgw']}
            ]
        )
        cgw_id = cgw['CustomerGateways'][0]['CustomerGatewayId']

        self.ec2_client.delete_customer_gateway(
            CustomerGatewayId=cgw_id,
        )
        self.logger.info('Customer gateway ' +cgw_id+ ' has been deleted')
        return

    def set_aws_vpn_connection(self, aws_cust_gw_id, tunnel_type, aws_vpn_gw_id, dry_run_flag, aws_static_routes_only_flag, base_name):
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

        self.ec2_client.create_tags(
            Resources=[
                vpn_id,
            ],
            Tags=[
                {
                    'Key': 'Name',
                    'Value': base_name+'-vpn',
                },
            ],
        )

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

        vpn_details_file_name = 'VPN_details_'+vpn_id+'.xml'
        tree = ElementTree.ElementTree()
        setting_root = tree._setroot(xml_tree_root)
        tree.write(vpn_details_file_name, encoding='utf-8', xml_declaration=True)
        self.logger.info('VPN connection details file created: '+vpn_details_file_name)

        return vpn_id, xml_tree_root

    def del_aws_vpn_connection(self, base_name):
        vpn = self.ec2_client.describe_vpn_connections(
            Filters = [
                { 'Name': 'tag:Name', 'Values': [base_name+'-vpn']}
            ]
        )
        vpn_id = vpn['VpnConnections'][0]['VpnConnectionId']

        self.ec2_client.delete_vpn_connection(
            VpnConnectionId=vpn_id,
        )

        vpn_waiter = self.ec2_client.get_waiter('vpn_connection_deleted')
        vpn_waiter.wait(
            VpnConnectionIds=[
                vpn_id,
            ],
            WaiterConfig={
                'Delay': 10,
                'MaxAttempts': 6
            }
        )
        self.logger.info('VPN connection ' +vpn_id+ ' has been deleted')
        return

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

        meraki_vpns_resp = requests.get(meraki_api_url, headers=meraki_api_headers)
        meraki_3party_vpns = meraki_vpns_resp.json()

        if meraki_vpns_resp.status_code != 200:
            print(meraki_3party_vpns)
        else:
            self.logger.info('Meraki VPN connections have been retrieved')

        meraki_tunnel_endpoint_data = {
            "name": base_name,
            "publicIp": aws_tunnel_out_ip,
            "privateSubnets": [aws_subnet],
            "secret": aws_tunnel_psk,
            "ipsecPoliciesPreset": meraki_ipsec_policy
          }

        meraki_3party_vpns.append(meraki_tunnel_endpoint_data)

        peers = {
            'peers': meraki_3party_vpns
        }
        meraki_api_resp = requests.put(meraki_api_url, headers=meraki_api_headers,
                                        data=json.dumps(peers), verify=False)
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

    def del_aws_cform_stack(self, base_name):
        self.cf_client.delete_stack(
            StackName=base_name+'-stack',
        )

        waiter = self.cf_client.get_waiter('stack_delete_complete')

        waiter.wait(
            StackName=base_name+'-stack',
            WaiterConfig={
                'Delay': 10,
                'MaxAttempts': 60
            }
        )

        self.logger.info('Stack '+ base_name +'-stack has been deleted')
        return
