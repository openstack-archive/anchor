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
    'allow_backdoor': True,
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
    ('common_name',),
    ('alternative_names',),
    ('server_group',),
    ('extensions',),
    ('key_usage',),
    ('ca_status', {'ca_requested': False}),
]

validator_options = {
    'allowed_extensions': ['keyUsage', 'subjectAltName', 'basicConstraints', 'subjectKeyIdentifier'],
    'allowed_usage': ['Digital Signature', 'Key Encipherment', 'Non Repudiation', 'Certificate Sign', 'CRL Sign'],
    'allowed_domains': ['.hpcloud.net', 'clark.com'],
    'group_prefixes': {
        'nv': 'Nova_Team',
        'sw': 'Swift_Team',
        'bk': 'Bock_Team',
        'gl': 'Glance_Team',
        'cs': 'CS_Team',
        'mb': 'MB_Team',
        'ops': 'SysEng_Team',
        'qu': 'Neutron_Team',
    },
}

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
