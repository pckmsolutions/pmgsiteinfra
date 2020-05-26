from flask import Blueprint, current_app, jsonify, request, session, make_response, g
import requests
from werkzeug.exceptions import abort as werk_abort
from logging import LoggerAdapter

class RequestContextLogAdapter(LoggerAdapter):
    def __init__(self, logger, context_info_formatter):
        super(RequestContextLogAdapter, self).__init__(logger, {})
        self.context_info_formatter = context_info_formatter

    def process(self, msg, kwargs):
        return f'<{self.context_info_formatter(request, session)}> {msg}', kwargs

def add_request_logger(app, context_info_formatter):
    def set_log_context():
        request.logger = RequestContextLogAdapter(current_app.logger, context_info_formatter)
    app.before_request(set_log_context)

def get_info_blueprint(app_info):
    info_bp = Blueprint('__siteinfo__', __name__)
    
    @info_bp.route('', methods=['GET', ])
    def get():
        def _log(level):
            if level in request.args:
                getattr(request.logger, level)(request.args.get(level))
    
        _log('debug')
        _log('info')
        _log('error')
        if 'exception' in request.args:
            raise Exception(request.args.get('exception'))
    
        from yaml import safe_load
        with open(current_app.config['DEPLOY_INFO_FILE']) as f:
           return jsonify({**safe_load(f.read()), **app_info})

    return info_bp

def abort(error_code, **kwargs):
    params= ', '.join([f'{k}={v}' for (k,v) in kwargs.items()])
    current_app.logger.info(f'Aborting call with {error_code.name} ({params})')
    werk_abort(error_response(error_code, **kwargs))

def error_response(error_code, **kwargs):
    return make_response(jsonify(**{**kwargs, **dict(error=error_code.value[0])}), error_code.value[1])

