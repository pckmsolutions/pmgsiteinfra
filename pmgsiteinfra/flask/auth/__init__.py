from authlib.oidc.core import CodeIDToken
from authlib.jose import jwt
from authlib.integrations.flask_client import OAuth
from flask import redirect, url_for, session, g, request
from logging import getLogger
import requests
from functools import wraps

logger = getLogger(__name__)

def access_token(key=None):
    return _session_dict('auth_access_token', key)

def id_token(key=None):
    return _session_dict('auth_id_token', key)

def _session_dict(sess_key, sub_key=None):
    dic = session.get(sess_key)
    if not dic:
        return None
    return dic if not sub_key else dic[sub_key]

def is_user_logged_on():
    return bool(access_token())

class AuthServerCallError(Exception):
    @staticmethod
    def wrap_call(call, *args, **vargs):
        resp = call(*args, **vargs)
        if 200 <= resp.status_code <= 299:
            return resp.json()
        raise AuthServerCallError()

class AuthApp(OAuth):
    def __init__(self, app, logon_endpoint):
        super(AuthApp, self).__init__(app) #TODO, cache=self.cache)
        app.before_request(self._before_request)
        app.after_request(self._after_request)
        self.id_token_certs = None
        self.logon_endpoint = logon_endpoint
        self.logon_hooks = []

    def register(self, **reg_args):
        super(AuthApp, self).register('govsieauth', **reg_args)

    def _before_request(self):
        pass

    def _after_request(self, response):
        return response

    def register_logon_hook(self, call):
        self.logon_hooks.append(call)

    #def logon_page_endpoing(self, redirect_endpoint):
    #    return self.govsieauth.authorize_redirect(redirect_url)#, **params)
    @property
    def server_metadata(self):
        self.govsieauth._load_server_metadata()
        return self.govsieauth.server_metadata

    def logon_page(self, redirect_endpoint, render = None):
        args = {k:v for k, v in request.args.items() if k in ['client_id', 'redirect_uri', 'state']}
        if args:
            if not render:
                raise RuntimeError('To re-enter logon page a render function is required.')
            return render(auth_url=self.server_metadata['authorization_endpoint'], **args)
    
        redirect_url = url_for(redirect_endpoint, _external=True)
    
        return self.govsieauth.authorize_redirect(redirect_url)#, **params)
    
    def get_oauth2_certs(self):
        if not self.id_token_certs:
            self.id_token_certs = AuthServerCallError.wrap_call(self.govsieauth.get, self.server_metadata['jwks_uri'])
        return self.id_token_certs
    
    
    def authorise_flow(self, default_redirect_endpoint):
        access_token = self.govsieauth.authorize_access_token()
    
        key = self.get_oauth2_certs()
        id_token = jwt.decode(access_token['id_token'], key, claims_cls=CodeIDToken)
        id_token.validate()

        user_info = AuthServerCallError.wrap_call(self.govsieauth.get, self.server_metadata['userinfo_endpoint'])
        self._create_session(access_token=access_token, id_token=id_token, user_info=user_info)

        redirect_endpoint = session['requested_page'] if 'requested_page' in session else url_for(default_redirect_endpoint)
    
        return redirect(redirect_endpoint)

    def user_id(self):
        return id_token('sub')

    def user_info(self):
        return session.get('auth_user_info', None)
        #if not is_user_logged_on():
        #    return None

        #logger.debug(f'AUTH: Userinfo using: {self.govsieauth.server_metadata["userinfo_endpoint"]}')
        #ui = self.govsieauth.get(self.govsieauth.server_metadata['userinfo_endpoint'], token=access_token())
        #logger.debug(f'AUTH: Userinfo: {ui}')
        #return ui.json()

    def logout(self):
        self._destroy_session()

    def require_logon(self, f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if 'auth_id_token' not in session:
                session['requested_page'] = request.url
                return redirect(url_for(self.logon_endpoint))
            return f(*args, **kwargs)
    
        return decorated

    def _create_session(self, access_token, id_token, user_info):
        logger.debug(f'Creating session for {user_info}')
        session['auth_access_token'] = access_token
        session['auth_id_token'] = id_token
        session['auth_user_info'] = user_info

        for hook in self.logon_hooks:
            hook(user_info)
    
    def _destroy_session(self):
        for k in ['auth_access_token', 'auth_id_token', 'auth_user_info']:
            if k in session:
                del session[k]

