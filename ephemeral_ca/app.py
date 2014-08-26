from pecan import make_app
from . import validators


class ConfigValidationException(Exception):
    pass


def validate_config(conf):
    if not hasattr(conf, "auth") or not conf.auth:
        raise ConfigValidationException("No authentication configured")

    if not hasattr(conf, "validators"):
        raise ConfigValidationException("No validators configured")

    for i, validators_list in enumerate(conf.validators):
        name = validators_list.get("name")
        if not name:
            raise ConfigValidationException("Validator set %i is missing a name", i+1)

        if not validators_list.get("steps"):
            raise ConfigValidationException("Validator set <%s> is missing validation steps", name)

        for step in validators_list["steps"]:
            if not isinstance(step, tuple):
                raise ConfigValidationException("Validator set <%s> contains a step that's <%s> and not a tuple", name, step)

            if len(step) == 0:
                raise ConfigValidationException("Validator set <%s> contains a step with no validator name", name)

            if not hasattr(validators, step[0]):
                raise ConfigValidationException("Validator set <%s> contains an unknown validator <%s>", name, step[0])


def setup_app(config):
    app_conf = dict(config.app)

    validate_config(config)

    return make_app(
        app_conf.pop('root'),
        logging=getattr(config, 'logging', {}),
        **app_conf
    )
