from authlib.oidc.core import CodeIDToken
from authlib.jose import jwt
from authlib.integrations.flask_client import OAuth
from flask import redirect, url_for, session, g
from logging import getLogger
import requests
from functools import wraps

logger = getLogger(__name__)

def _create_session(access_token, id_token, user_info):
    logger.debug(f'Creating session for {user_info}')
    session['auth_access_token'] = access_token
    session['auth_id_token'] = id_token
    session['auth_user_info'] = user_info

def _destroy_session():
    for k in ['auth_access_token', 'auth_id_token', 'auth_user_info']:
        if k in session:
            del session[k]

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
        self.register('govsieauth')
        app.before_request(self._before_request)
        app.after_request(self._after_request)
        self.id_token_certs = None
        self.logon_endpoint = logon_endpoint

    def _before_request(self):
        pass

    def _after_request(self, response):
        return response

    def logon_page(self, redirect_endpoint):
        
        
        #params = dict(scope='openid+profile', access_type='offline', response_type='code')
    
        redirect_url = url_for(redirect_endpoint, _external=True)
    
        return self.govsieauth.authorize_redirect(redirect_url)#, **params)
    
    def get_oauth2_certs(self):
        if not self.id_token_certs:
            self.id_token_certs = AuthServerCallError.wrap_call(self.govsieauth.get, self.govsieauth.server_metadata['jwks_uri'])
        return self.id_token_certs
    
    
    def authorise_flow(self, redirect_endpoint):
        access_token = self.govsieauth.authorize_access_token()
    
        key = self.get_oauth2_certs()
        id_token = jwt.decode(access_token['id_token'], key, claims_cls=CodeIDToken)
        id_token.validate()

        user_info = AuthServerCallError.wrap_call(self.govsieauth.get, self.govsieauth.server_metadata['userinfo_endpoint'])
        _create_session(access_token=access_token, id_token=id_token, user_info=user_info)
    
        return redirect(url_for(redirect_endpoint))

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
        _destroy_session()

    def require_logon(self, f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if 'auth_id_token' not in session:
                g.requested_page = f
                return redirect(url_for(self.logon_endpoint))
            return f(*args, **kwargs)
    
        return decorated

