server = {
    'port': '5000',
    'host': '0.0.0.0'
}

# Pecan Application Configurations
app = {
    'root': 'ephemeral_ca.controllers.RootController',
    'modules': ['ephemeral_ca'],
    # 'static_root': '%(confdir)s/public',
    # 'template_path': '%(confdir)s/${package}/templates',
    'debug': True,
    'errors': {
        '404': '/error/404',
        '__force_dict__': True
    }
}

auth = {
    'static': {
        'user': 'woot',
        'secret': 'woot',
    },
    # 'ldap': {
    #     'host': "aw2clouddc01.hpcloud.ms",
    #     'domain': "hpcloud.ms",
    #     'base': "CN=Users,DC=hpcloud,DC=ms",
    # },
    # 'keystone': {
    #     'url': 'https://keystone.example.com:35357',
    # },
}

validators = [
    {
        "name": "default",
        "steps": [
            ('common_name', {'allowed_domains': ['.hpcloud.net', 'clark.com']}),
            ('alternative_names', {'allowed_domains': ['.hpcloud.net', 'clark.com']}),
            ('server_group', {'group_prefixes': {
                'nv': 'Nova_Team',
                'sw': 'Swift_Team',
                'bk': 'Bock_Team',
                'gl': 'Glance_Team',
                'cs': 'CS_Team',
                'mb': 'MB_Team',
                'ops': 'SysEng_Team',
                'qu': 'Neutron_Team',
                }}),
            ('extensions', {'allowed_extensions': ['keyUsage', 'subjectAltName', 'basicConstraints', 'subjectKeyIdentifier']}),
            ('key_usage', {'allowed_usage': ['Digital Signature', 'Key Encipherment', 'Non Repudiation', 'Certificate Sign', 'CRL Sign']}),
            ('ca_status', {'ca_requested': False}),
            ('source_cidrs', {'cidrs': ["127.0.0.0/8"]}),
        ]
    },
    {
        "name": "ip",
        "steps": [
            ('common_name', {'allowed_networks': ['127/8']}),
            ('alternative_names', {'allowed_networks': ['127/8']}),
            ('ca_status', {'ca_requested': False}),
            ('source_cidrs', {'cidrs': ["127.0.0.0/8"]}),
        ]
    },
]

ca = {
    'cert_path': "CA/root-ca.crt",
    'key_path': "CA/root-ca-unwrapped.key",
    'output_path': "certs",
    'valid_hours': 24,
    'signing_hash': "sha1",
}

logging = {
    'loggers': {
        'root': {'level': 'INFO', 'handlers': ['console']},
        'ephemeral_ca': {'level': 'DEBUG', 'handlers': ['console']}
    },
    'handlers': {
        'console': {
            'level': 'DEBUG',
            'class': 'logging.StreamHandler',
            'formatter': 'simple'
        }
    },
    'formatters': {
        'simple': {
            'format': ('%(asctime)s %(levelname)-5.5s [%(name)s]'
                       '[%(threadName)s] %(message)s')
        }
    }
}
