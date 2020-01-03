import urllib3
from aws_autobuild import AWSAutoBuild

def main():

    # Disable insecure warning output
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    # Create object of autobuild class
    autotearer = AWSAutoBuild('build_schema.py')

    autotearer.logger.info('-------------- Auto tear down launched! --------------')

    # Retrieve all Meraki related information
    meraki_api_headers = autotearer.set_meraki_headers(
                            autotearer.config['meraki']['api_key'],
                            autotearer.config['meraki']['content_type']
                         )

    if autotearer.config['meraki']['org_id'] == '-1':
      meraki_org_id = autotearer.get_meraki_org_id(
        meraki_api_headers, autotearer.config['meraki']['base_uri'],
        autotearer.config['meraki']['org_name']
      )
    else:
      meraki_org_id = autotearer.config['meraki']['org_id']

    meraki_public_ip = autotearer.get_meraki_ip(
                            meraki_api_headers,
                            autotearer.config['meraki']['base_uri'],
                            meraki_org_id,
                            autotearer.config['meraki']['device_serial']
                       )

    autotearer.logger.info('-------------- Cloudform tear down started! ----------------')
    autotearer.del_aws_cform_stack(autotearer.config['project']['base_name'])
    autotearer.logger.info('-------------- Cloudform tear down complete! ----------------')

    autotearer.logger.info('-------------- AWS tear down started! ----------------')
    autotearer.del_aws_vpn_connection(autotearer.config['project']['base_name'])
    autotearer.del_aws_vpn_gw(autotearer.config['project']['base_name'])
    autotearer.del_aws_customer_gw(autotearer.config['project']['base_name'])
    autotearer.del_aws_sec_group(autotearer.config['project']['base_name'])
    autotearer.del_aws_inet_gw(autotearer.config['project']['base_name'])
    autotearer.del_aws_subnet(autotearer.config['project']['base_name'])
    autotearer.del_aws_route_table(autotearer.config['project']['base_name'])
    autotearer.del_aws_vpc(autotearer.config['project']['base_name'])
    autotearer.del_aws_keypair(autotearer.config['project']['base_name'])
    autotearer.logger.info('-------------- AWS tear down complete! ----------------')

if __name__== "__main__":
  main()
