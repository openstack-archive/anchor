from collections import namedtuple

AuthDetails = namedtuple('AuthDetails', ['username', 'groups'])
AUTH_FAILED = object()
