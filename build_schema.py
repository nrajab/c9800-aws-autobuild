{
    'project': {
        'required': True,
        'type': 'dict',
        'schema': {
            'base_name': {'required': True, 'type': 'string'}
        }
    },
    'aws': {
        'required': True,
        'type': 'dict',
        'schema': {
            'global': {
                'type': 'dict',
                'schema': {
                    'region': {'type': 'string'},
                    'zone': {'type': 'string'},
                    'dry_run_flag': {'type': 'boolean'},
                    'account': {'type': 'string'}
                }
            },
            'vpc': {
                'type': 'dict',
                'schema': {
                    'cidr_block': {'type': 'string'},
                    'subnet': {'type': 'string'},
                    'sec_group_descr': {'type': 'string'},
                    'sec_group_protocol': {'type': 'string'},
                    'sec_from_port': {'type': 'number'},
                    'sec_to_port': {'type': 'number'},
                    'cust_bgp_asn': {'type': 'number'},
                    'tunnel_type': {'type': 'string'},
                    'bgp_asn': {'type': 'number'},
                    'static_routes_flag': {'type': 'boolean'}
                }
            },
            'ec2': {
                'type': 'dict',
                'schema': {
                    'instance_type': {'type': 'string'},
                    'wlc_mgmt_ip': {'type': 'string'},
                    'cloud_form_template_url': {'type': 'string'},
                    'wlc_user': {'type': 'string'},
                    'wlc_pass': {'type': 'string'}
                }
            }
        }
    },
    'meraki': {
        'required': True,
        'type': 'dict',
        'schema': {
            'api_key': {'type': 'string'},
            'org_name': {'type': 'string'},
            'org_id': {'type': 'string'},
            'base_uri': {'type': 'string'},
            'device_serial': {'type': 'string'},
            'content_type': {'type': 'string'},
            'subnet': {'type': 'string'},
            'ipsec_policy': {'type': 'string'},
            'vpn_net_tags': {'type': 'list'}
        }
    }
}
