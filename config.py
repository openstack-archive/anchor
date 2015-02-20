server = {
    'port': '5000',
    'host': '0.0.0.0'
}

# Pecan Application Configurations
app = {
    'root': 'anchor.controllers.RootController',
    'modules': ['anchor'],
    # 'static_root': '%(confdir)s/public',
    # 'template_path': '%(confdir)s/${package}/templates',
    'debug': True,
    'errors': {
        '404': '/error/404',
        '__force_dict__': True
    }
}
