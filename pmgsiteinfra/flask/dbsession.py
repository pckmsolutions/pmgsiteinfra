
from flask.sessions import SessionInterface
from flask.sessions import SessionMixin
from werkzeug.datastructures import CallbackDict
from itsdangerous import Signer, BadSignature, want_bytes
from pmgdbutil import DbDict
from uuid import uuid4
from logging import getLogger
try:
    import cPickle as pickle
except ImportError:
    import pickle

logger = getLogger(__name__)

class DbSession(CallbackDict, SessionMixin):
    def __init__(self, initial=None, sid=None, permanent=None):
        def on_update(self):
            self.modified = True
        CallbackDict.__init__(self, initial, on_update)
        self.sid = sid
        if permanent:
            self.permanent = permanent
        self.modified = False


class DbSessionInterface(SessionInterface):
    def __init__(self, connection_pool, **kwargs):
        self.permanent = kwargs.get('permanent', True)
        self.cache = DbDict(connection_pool, **{**kwargs, **dict(max_key_size=60, max_val_size=6000)})

    def open_session(self, app, request):
        logger.debug('Open session')
        sid = request.cookies.get(app.session_cookie_name)
        if not sid:
            sid = self._generate_sid()
            logger.debug(f'Create new session: {sid}')
            return DbSession(sid=sid, permanent=self.permanent)

        signer = self._get_signer(app)
        if signer:
            try:
                sid_as_bytes = signer.unsign(sid)
                sid = sid_as_bytes.decode()
            except BadSignature:
                sid = self._generate_sid()
                return DbSession(sid=sid, permanent=self.permanent)

        data = self.cache.get(sid)
        if data is not None:
            return DbSession(data, sid=sid)
        return DbSession(sid=sid, permanent=self.permanent)

    def save_session(self, app, session, response):
        logger.debug(f'Save session: {session.sid}')

        domain = self.get_cookie_domain(app)
        path = self.get_cookie_path(app)
        #if not session:
        #    if session.modified:
        #        del self.cache[session.sid]
        #        response.delete_cookie(app.session_cookie_name, domain=domain, path=path)
        #    return

        httponly = self.get_cookie_httponly(app)
        secure = self.get_cookie_secure(app)
        expires = self.get_expiration_time(app, session)
        data = dict(session)
        logger.debug(f'Saving session: {data}')
        self.cache.set(session.sid, data, app.permanent_session_lifetime.total_seconds())
        signer = self._get_signer(app)
        if signer:
            session_id = signer.sign(want_bytes(session.sid))
        else:
            session_id = session.sid
        response.set_cookie(app.session_cookie_name, session_id,
                            expires=expires, httponly=httponly,
                            domain=domain, path=path, secure=secure)

    def _generate_sid(self):
        return str(uuid4())

    def _get_signer(self, app):
        if not app.secret_key:
            return None
        return Signer(app.secret_key, salt='stuff-session', key_derivation='hmac')




