import logging
import urllib3
from aws_autobuild import AWSAutoBuild

def main():

    # Disable insecure warning output
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Create object of autobuild class
    autobuilder = AWSAutoBuild('build_schema.py')

    # Retrieve all Meraki related information
    meraki_api_headers = autobuilder.set_meraki_headers(autobuilder.config['meraki']['api_key'], autobuilder.config['meraki']['content_type'])

    if autobuilder.config['meraki']['org_id'] == '-1':
      meraki_org_id = autobuilder.get_meraki_org_id(meraki_api_headers, autobuilder.config['meraki']['base_uri'], autobuilder.config['meraki']['org_name'])
    else:
      meraki_org_id = autobuilder.config['meraki']['org_id']

    meraki_public_ip = autobuilder.get_meraki_ip(meraki_api_headers, autobuilder.config['meraki']['base_uri'], meraki_org_id, autobuilder.config['meraki']['device_serial'])

    autobuilder.logger.info('-------------- AWS VPN setup started! ------------------')

    # Set all AWS parameters and constructs
    autobuilder.set_aws_keypair(autobuilder.config['project']['base_name'])
    vpc = autobuilder.set_aws_vpc(autobuilder.config['aws']['vpc']['cidr_block'], autobuilder.config['project']['base_name'])
    igw = autobuilder.set_aws_inet_gw(vpc)
    aws_routetable = autobuilder.set_aws_default_route(vpc, igw)
    aws_subnet = autobuilder.set_aws_subnet(vpc, autobuilder.config['aws']['global']['zone'], autobuilder.config['aws']['vpc']['subnet'], aws_routetable)
    aws_sec_group = autobuilder.set_aws_sec_group(autobuilder.config['project']['base_name'], autobuilder.config['aws']['vpc']['sec_group_descr'], vpc, autobuilder.config['aws']['vpc']['sec_group_protocol'], autobuilder.config['aws']['vpc']['sec_from_port'], autobuilder.config['aws']['vpc']['sec_to_port'])
    aws_vpn_gw_id = autobuilder.set_aws_vpn_gw(autobuilder.config['aws']['vpc']['tunnel_type'], autobuilder.config['aws']['vpc']['bgp_asn'], autobuilder.config['aws']['global']['dry_run_flag'], autobuilder.config['project']['base_name'], vpc)
    autobuilder.set_aws_route_propagation(aws_vpn_gw_id, aws_routetable)
    aws_cust_gw_id = autobuilder.set_aws_customer_gw(autobuilder.config['aws']['vpc']['cust_bgp_asn'], meraki_public_ip, autobuilder.config['aws']['vpc']['tunnel_type'], autobuilder.config['project']['base_name'], autobuilder.config['aws']['global']['dry_run_flag'])
    aws_vpn_id, aws_vpn_xml_tree_root = autobuilder.set_aws_vpn_connection(aws_cust_gw_id, autobuilder.config['aws']['vpc']['tunnel_type'], aws_vpn_gw_id, autobuilder.config['aws']['global']['dry_run_flag'], autobuilder.config['aws']['vpc']['static_routes_flag'])
    autobuilder.set_aws_remote_subnet_route(autobuilder.config['meraki']['subnet'], aws_vpn_id)
    aws_tunnel_out_ip, aws_tunnel_psk = autobuilder.get_aws_vpn_connection_details(aws_vpn_xml_tree_root)

    autobuilder.logger.info('-------------- AWS VPN setup complete! ------------------')
    autobuilder.logger.info('------------- Meraki VPN setup started! -----------------')

    # Configure Meraki end point tunnel termination
    autobuilder.set_meraki_vpn_connection(meraki_org_id, autobuilder.config['meraki']['base_uri'], autobuilder.config['project']['base_name'], aws_tunnel_out_ip, aws_tunnel_psk, autobuilder.config['aws']['vpc']['subnet'], autobuilder.config['meraki']['ipsec_policy'], meraki_api_headers)

    autobuilder.logger.info('------------- Meraki VPN setup complete! ----------------')
    autobuilder.logger.info('------------- C9800-CL launch started! ------------------')

    # Create an EC2 instance of C9800-CL and apply the cloudformation template with all parameters
    autobuilder.launch_c9800_cloudform(autobuilder.config['project']['base_name'], autobuilder.config['aws']['ec2']['cloud_form_template_url'], aws_subnet, aws_sec_group, autobuilder.config['aws']['ec2']['wlc_mgmt_ip'], autobuilder.config['aws']['ec2']['wlc_user'], autobuilder.config['aws']['ec2']['wlc_pass'], autobuilder.config['aws']['ec2']['instance_type'])

    autobuilder.logger.info('-------------- C9800-CL launch complete! ----------------')

if __name__== "__main__":
  main()
