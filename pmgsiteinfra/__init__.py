def configure_logging(config_file):
    from logging.config import dictConfig
    from yaml import safe_load
    with open(config_file, 'rt') as f:
        dictConfig(safe_load(f.read()))
