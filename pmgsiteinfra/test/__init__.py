from unittest import TestCase
from unittest.mock import patch, Mock, MagicMock
import mysql.connector as dbconnector
from contextlib import contextmanager
import subprocess
from pmgdbutil import DbConnectionPool
from logging import getLogger

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

class FlywayDbTestCase(DbTestCase):
    def migrate(self):
        subprocess.run(['flyway', f'-url=jdbc:mysql://{self.MYSQL_HOST}:{self.MYSQL_PORT}/{self.MYSQL_DB}',
            f'-user={self.MYSQL_USER}',
            f'-password={self.MYSQL_PASSWORD}',
            f'-locations=filesystem:{self.MYSQL_DB_SCRIPT_DIR}', 'migrate'])

try:
    from yoyo import read_migrations, get_backend
    class YoyoDbTestCase(DbTestCase):
        def migrate(self):
            backend = get_backend(f'mysql://{self.MYSQL_USER}:{self.MYSQL_PASSWORD}@{self.MYSQL_HOST}:{self.MYSQL_PORT}/{self.MYSQL_DB}')
            migrations = read_migrations(self.MYSQL_DB_SCRIPT_DIR)
            
            with backend.lock():
                backend.apply_migrations(backend.to_apply(migrations))
                backend.rollback_migrations(backend.to_rollback(migrations))
except ImportError:
    pass

class AppTestBase(CommonTestBase, FlywayDbTestCase):
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

    def cursor_has_columns(self, *columns):
        self.mock_cursor.description = [(col,) for col in columns]

    def cursor_returns_rows(self, rows):
        self.mock_cursor.fetchone = lambda : rows[0]
        self.mock_cursor.fetchall = lambda : rows

