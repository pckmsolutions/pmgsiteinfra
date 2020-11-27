from authlib.oidc.core import CodeIDToken
from authlib.jose import jwt
from authlib.integrations.flask_client import OAuth
from flask import redirect, url_for, session, g, request, render_template
from logging import getLogger
from functools import wraps
from werkzeug.exceptions import HTTPException, BadRequestKeyError
from werkzeug.security import gen_salt

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

class AuthServerCallError(Exception):
    def __init__(self, response=None):
        self.response = response

    @property
    def json(self):
        try:
            return self.response.json()
        except:
            pass
        return None

    def __repr__(self_):
        return f'AuthServerCallError({self.response!r})'

OK_RANGE = range(200,300)

def wrap_call(call, allowed_codes, *args, **vargs):
    resp = call(*args, **vargs)
    if resp.status_code in allowed_codes:
        return resp.json()
    raise AuthServerCallError(response=resp)

def wrap_call_200s(call, *args, **vargs):
    return wrap_call(call, OK_RANGE, *args, **vargs)

class AuthApp(OAuth):
    def __init__(self, app, logon_endpoint, api_token):
        super(AuthApp, self).__init__(app) #TODO, cache=self.cache)
        app.before_request(self._before_request)
        app.after_request(self._after_request)
        self.id_token_certs = None
        self.logon_endpoint = logon_endpoint
        self.logon_hooks = []
        self.api_token = api_token

    def register(self, **reg_args):
        super(AuthApp, self).register('govsieauth', **reg_args)

    def _before_request(self):
        pass

    def _after_request(self, response):
        return response

    def register_logon_hook(self, call):
        self.logon_hooks.append(call)

    @property
    def server_metadata(self):
        self.govsieauth._load_server_metadata()
        return self.govsieauth.server_metadata

    def logon_page(self, redirect_endpoint, render = None):
        args = request.args.to_dict()

        if all(k in args for k in ['client_id', 'redirect_uri', 'state']):
            if not render:
                raise RuntimeError('To re-enter logon page a render function is required.')
            return render(auth_url=self.server_metadata['authorization_endpoint'], **args)
    
        redirect_url = url_for(redirect_endpoint, _external=True)
        if not 'requested' in args:
            session.pop('requested_page', None)
    
        return self.govsieauth.authorize_redirect(redirect_url, **args)
    
    def get_oauth2_certs(self):
        if not self.id_token_certs:
            self.id_token_certs = wrap_call_200s(self.govsieauth.get, self.server_metadata['jwks_uri'])
        return self.id_token_certs
    
    
    def authorise_flow(self, default_redirect_endpoint):
        access_token = self.govsieauth.authorize_access_token()
    
        key = self.get_oauth2_certs()
        id_token = jwt.decode(access_token['id_token'], key, claims_cls=CodeIDToken)
        id_token.validate()

        user_info = wrap_call_200s(self.govsieauth.get, self.server_metadata['userinfo_endpoint'])
        self._create_session(access_token=access_token, id_token=id_token, user_info=user_info)

        redirect_endpoint = session.pop('requested_page', url_for(default_redirect_endpoint))
    
        return redirect(redirect_endpoint)

    def user_id(self):
        return id_token('sub')

    def is_user_logged_on(self):
        return bool(access_token())

    def user_info(self):
        return session.get('auth_user_info', None)
        #if not is_user_logged_on():
        #    return None

        #logger.debug(f'AUTH: Userinfo using: {self.govsieauth.server_metadata["userinfo_endpoint"]}')
        #ui = self.govsieauth.get(self.govsieauth.server_metadata['userinfo_endpoint'], token=access_token())
        #logger.debug(f'AUTH: Userinfo: {ui}')
        #return ui.json()
    def _api_endpoint(self, *items):
        return '/'.join([*[self.server_metadata["api_endpoint"]], *items]), \
                dict(headers={'Authorization': f'SSWS {self.api_token}'},
                        withhold_token=True)
            #dict(token_type='ssws', access_token='DI5TSgB62NCehyP0KqgBFcXCCU1399omoagEAvnVezYkBI8K.MjZxy9AdtqMxH3uxqtfXfWoO')

    def get_user(self, uid_or_email):
        endpoint, kwargs = self._api_endpoint('users')
        user_detail_resp = self.govsieauth.get(endpoint,
                params={'uid_or_email': uid_or_email},
                **kwargs)
        if user_detail_resp.status_code in OK_RANGE:
            return user_detail_resp.json()
        if user_detail_resp.status_code == 404:
            return None
        raise AuthServerCallError(response=user_detail_resp)

    def get_user_profile(self, uid_or_email):
        user = self.get_user(uid_or_email)
        return user and user['profile']

    def get_user_id(self, uid_or_email):
        user = self.get_user(uid_or_email)
        return user and user['uid']

    def create_user(self, username, password, firstname, lastname, email):
        endpoint, kwargs = self._api_endpoint('users')

        return wrap_call_200s(self.govsieauth.put, endpoint,
                json={
                    'username': username,
                    'password': password,
                    'firstname': firstname,
                    'lastname': lastname,
                    'email': email},
                **kwargs)

    def get_reset_token(self, username):
        endpoint, kwargs = self._api_endpoint('users', 'lifecycle/reset')

        return wrap_call_200s(self.govsieauth.get, endpoint,
                params={'uid_or_email': username},
                **kwargs)

    def reset_token(self, token, password):
        endpoint, kwargs = self._api_endpoint('users', 'lifecycle/reset')

        return wrap_call_200s(self.govsieauth.put, endpoint,
                json={
                    'token': token,
                    'password': password},
                **kwargs)

    def activate_user(self, token):
        endpoint, kwargs = self._api_endpoint('users', 'activate')

        return wrap_call_200s(self.govsieauth.put, endpoint, 
                json={'token': token},
                **kwargs)

    def logout(self):
        self._destroy_session()

    def require_logon(self, f):
        @wraps(f)
        def decorated(*args, **kwargs):
            if not AuthApp._is_logged_on():
                session['requested_page'] = request.url
                return redirect(url_for(self.logon_endpoint, requested=True))
            return f(*args, **kwargs)
    
        return decorated

    @staticmethod
    def _is_logged_on():
        return 'auth_id_token' in session

    @property
    def logged_on(self):
        return AuthApp._is_logged_on()

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

    def handle_logon(self, logon_html, root_authorise):
        logon_args = request.args.to_dict()
        def render(**args):
            return render_template(logon_html, **{**logon_args, **args})
        
        return self.logon_page(root_authorise, render=render)
    
    def handle_authorise(self, next_home, root_logon):
        try:
            return self.authorise_flow(next_home)
        except BadRequestKeyError:
            return redirect(url_for(root_logon, message='auth'))
    
    def handle_activate(self, token, root_logon, root_regmsg):
        try:
            resp = self.activate_user(token)
            return redirect(url_for(root_logon, message='activated'))
        except AuthServerCallError as err:
            json = err.json
            if json and 'error' in json and json['error'] == 'E0003':
                return redirect(url_for(root_regmsg, message='no_token_reg'))
            return redirect(url_for(root_regmsg, message='bad_user'))
    
    def handle_regmsg(self, regmsg_html):
        return render_template('regmsg.html',
                message=request.values.get('message'))
    
    def handle_reset(self, reset_html, root_regmsg,
            email_reset_subject, email_reset_body):
        if 'token' in request.args:
            return self.reset_tok(request.args['token'])
        if request.method == 'GET':
            return render_template(reset_html, message=request.values.get('message'))
    
        email = request.values['email']
    
        try:
            resp = self.get_reset_token(username=email)
        except AuthServerCallError as err:
            return redirect(url_for(root_regmsg, message='bad_user'))
    
        send_email(addr=email, subject_template=email_reset_subject,
                body_template=email_reset_body, token=resp['token'])
        
        return redirect(url_for(root_regmsg, message='reset'))
    
    def handle_reset_tok(self, token, setpassword_html, root_regmsg, root_logon):
        if request.method == 'GET':
            return render_template(setpassword_html)
        try:
            if request.values.get('password') != request.values.get('password'):
                raise RuntimeError('Passwords do not match')
            resp = self.reset_token(token,
                    request.values.get('password'))
        except AuthServerCallError as err:
            json = err.json
            if json and 'error' in json and json['error'] == 'E0003':
                return redirect(url_for(root_regmsg, message='no_token_res'))
            return redirect(url_for(root_regmsg, message='bad_user'))
    
        return redirect(url_for(root_logon, message='reset'))
    
    def handle_register(self, setpassword_html, root_register, root_reset, 
            root_regmsg, email_activate_subject, email_activate_body,
            get_newuser):
        if request.method == 'GET':
            return render_template(setpassword_html,
                    message=request.values.get('message'))
    
        if request.values.get('password') != request.values.get('password'):
            raise RuntimeError('Passwords do not match')
    
        def no_perm():
            return redirect(url_for(root_register, message='perm'))
    
        email = request.values['email']
        user_info = get_newuser(username = email)
        if user_info is None:
            return redirect(url_for(root_register, message='not_found'))
    
        try:
            resp = self.create_user(username=email,
                    password=request.values['password'],
                    firstname=user_info.firstname,
                    lastname=user_info.lastname,
                    email=email)
        except AuthServerCallError as err:
            logger.error('Auth server call error %s', err)
            json = err.json
            if json and 'error' in json and json['error'] == 'E0004':
                return redirect(url_for(root_reset, message='user_exists'))
    
            logger.error('Auth has failed for unknown reason')
            return redirect(url_for(root_regmsg, message='unknown'))
    
        send_email(addr=email, subject_template=email_activate_subject,
                body_template=email_activate_body, token=resp['token'])
        
        return redirect(url_for(root_regmsg, message='email'))
    
    def handle_logout(self, root_slash):
        self.logout()
        return redirect(url_for(root_slash))
