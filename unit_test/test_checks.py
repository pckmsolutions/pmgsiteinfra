from unittest import TestCase
from unittest.mock import Mock
from pmgsiteinfra.util import check_dict

class ChecksTestCase(TestCase):

    def test_checks_dict_with_tup(self):
        abort = Mock()
        check_dict(dict(hello=1), abort, ('hello',))
        abort.assert_not_called()

    def test_checks_dict_with_item(self):
        abort = Mock()
        check_dict(dict(hello=1), abort, 'hello')
        abort.assert_not_called()

    def test_checks_dict_with_fail(self):
        abort = Mock()
        check_dict(dict(hello=1), abort, 'goodbye')
        abort.assert_called_once()

    def test_checks_dict_with_pass_option(self):
        abort = Mock()
        check_dict(dict(hello=1), abort, ('goodbye', 'agag', 'hello'))
        abort.assert_not_called()

    def test_checks_dict_with_fail_option(self):
        abort = Mock()
        check_dict(dict(hello=1), abort, ('goodbye', 'agag', 'helloo'))
        abort.assert_called_once()

    def test_checks_dict_with_pass_option_big(self):
        abort = Mock()
        check_dict(dict(hello=1, yoko='in vain', was='it', these='the pros and cons of hitchiking'), abort, ('goodbye', 'agag', 'helloo', 'these'))
        abort.assert_not_called()

    def test_checks_mult(self):
        abort = Mock()
        check_dict(dict(hello=1, yoko='in vain', was='it', these='the pros and cons of hitchiking'), abort,
                ('goodbye', 'agag', 'helloo', 'these'), 'was', 'yoko', 'hello')
        abort.assert_not_called()

    def test_checks_mult_fail(self):
        abort = Mock()
        check_dict(dict(hello=1, yoko='in vain', was='it', these='the pros and cons of hitchiking'), abort,
                ('goodbye', 'agag', 'helloo', 'these'), 'was', 'yoko', 'hello', 'cavalry')
        abort.assert_called_once()



