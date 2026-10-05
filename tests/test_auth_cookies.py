from swiggy_hunter.auth.cookies import parse_cookie_string


def test_semicolon():
    assert parse_cookie_string("a=1; b=2") == {"a": "1", "b": "2"}


def test_newline():
    assert parse_cookie_string("a=1\nb=2") == {"a": "1", "b": "2"}


def test_json():
    assert parse_cookie_string('{"a":"1","b":"2"}') == {"a": "1", "b": "2"}


def test_netscape():
    line = ".swiggy.com\tTRUE\t/\tTRUE\t0\tsession\tabc123"
    assert parse_cookie_string(line) == {"session": "abc123"}
