from unittest import TestCase
from unittest.mock import patch, Mock, MagicMock
import mysql.connector as dbconnector
from contextlib import contextmanager
import subprocess
from pmgdbutil import DbConnectionPool
from logging import getLogger
from yoyo import read_migrations, get_backend
from itertools import count

logger = getLogger(__name__)

class CommonTestBase(TestCase):
    def app_context(self):
        return self.act_app.app_context()

class DbTestCase(object):
    def create_db(self):
        logger.info(f'Using test database {self.MYSQL_DB} with scripts directory {self.MYSQL_DB_SCRIPT_DIR}')

        with self.con_scope() as cur:
            cur.execute(f'CREATE DATABASE {self.MYSQL_DB}')

        self.migrate()

    def migrate(self):
        raise NotImplementedError()

    def drop_db(self):
        with self.con_scope() as cur:
            cur.execute(f'DROP DATABASE {self.MYSQL_DB}')

    @contextmanager
    def con_scope(self, db = None):
        try:
            conn = dbconnector.connect(host = self.MYSQL_HOST,
                    port = self.MYSQL_PORT,
                    user = self.MYSQL_USER,
                    password = self.MYSQL_PASSWORD,
                    database = db)

            cur = conn.cursor()

            yield cur

            conn.commit()
        except:
            conn.rollback()
            raise
        finally:
            cur.close()
            conn.close()

class YoyoDbTestCase(DbTestCase):
    def migrate(self):
        backend = get_backend(f'mysql://{self.MYSQL_USER}:{self.MYSQL_PASSWORD}@{self.MYSQL_HOST}:{self.MYSQL_PORT}/{self.MYSQL_DB}')
        migrations = read_migrations(self.MYSQL_DB_SCRIPT_DIR)
        
        with backend.lock():
            backend.apply_migrations(backend.to_apply(migrations))

class AppTestBase(CommonTestBase, YoyoDbTestCase):
    def setUp(self):
        self.create_db()
        self.act_app = self.create_app()
        self.app = self.act_app.test_client()

    def tearDown(self):
        self.drop_db()

class MockCursorTestBase(CommonTestBase):
    CONNECTION_POOL_CLASS = None

    def setUp(self):
        self.mock_cursor = Mock()
        self.mock_cursor.description = []
        self.mock_cursor.fetchone = lambda : []

        mock_connection = Mock()
        mock_connection.cursor.side_effect = lambda *args, **kwargs : self.mock_cursor

        mock_get_connection = MagicMock()
        mock_get_connection.__enter__.side_effect = lambda *args, **kwargs : mock_connection

        mock_connection_pool = Mock()
        mock_connection_pool.get_connection.side_effect = lambda *args, **kwargs : mock_get_connection

        if not self.CONNECTION_POOL_CLASS: # 
            raise ValueError('Set CONNECTION_POOL_CLASS to something like "govsietest.DbConnectionPool"')
        
        with patch(self.CONNECTION_POOL_CLASS) as pool_cls:
            pool_cls.return_value = mock_connection_pool
            self.act_app = self.create_app()

        self.app = self.act_app.test_client()
        self.call_count = 0

    def cursor_has_columns(self, *columns):
        self.mock_cursor.description = [(col,) for col in columns]

    def cursor_returns_rows(self, rows):
        self.mock_cursor.fetchone = lambda : rows[0]
        self.mock_cursor.fetchall = lambda : rows

    def cursor_returns_rows_on_call(self, *calls):
        def rows(ind=None):
            ret = calls[self.call_count]
            self.call_count += 1
            return ret if ind == None else ret[0] if ret else None
        self.mock_cursor.fetchone = lambda : rows(0)
        self.mock_cursor.fetchall = lambda : rows()
