import sqlite3

import pytest
import requests


def test_basic(knock_server_auth, get_ipc_result):
    resp = requests.post('http://127.0.0.1:8089/knock', headers={'authorization': f'bearer {knock_server_auth}'})
    resp.raise_for_status()
    assert get_ipc_result()['status'] == 'ok'


def test_auth_no_header(knock_server_auth, get_ipc_result):
    resp = requests.post('http://127.0.0.1:8089/knock')
    assert resp.status_code == 401
    assert not get_ipc_result()


@pytest.mark.parametrize(
    'token',
    [
        pytest.param('foo', id='unknown'),
        pytest.param('', id='empty'),
        pytest.param('x' * (1 << 14), id='big'),
    ],
)
def test_bad_auth(knock_server_auth, get_ipc_result, token):
    resp = requests.post('http://127.0.0.1:8089/knock', headers={'authorization': f'bearer {token}'})
    assert resp.status_code == 401
    assert not get_ipc_result()


def test_large_header(knock_server_auth, get_ipc_result):
    token = 'x' * (1 << 20)
    with pytest.raises(requests.ConnectionError):
        requests.post('http://127.0.0.1:8089/knock', headers={'authorization': f'bearer {token}'})
    assert not get_ipc_result()


def test_error_from_subprocess(knock_server_auth, set_ipc_return_value):
    set_ipc_return_value(-1)
    resp = requests.post('http://127.0.0.1:8089/knock', headers={'authorization': f'bearer {knock_server_auth}'})
    assert resp.status_code == 500


def test_last_login_update(knock_server_auth, sqlite_db_file):
    resp = requests.post('http://127.0.0.1:8089/knock', headers={'authorization': f'bearer {knock_server_auth}'})
    resp.raise_for_status()

    conn = sqlite3.connect(sqlite_db_file)
    cursor = conn.cursor()
    cursor.execute("SELECT last_login FROM auth WHERE key = ?", (knock_server_auth,))
    last_login = cursor.fetchone()[0]
    assert last_login is not None

    resp = requests.post('http://127.0.0.1:8089/knock', headers={'authorization': f'bearer {knock_server_auth}'})
    resp.raise_for_status()

    cursor.execute("SELECT last_login FROM auth WHERE key = ?", (knock_server_auth,))
    new_last_login = cursor.fetchone()[0]
    assert new_last_login is not None

    # verify timestamp was updated
    assert new_last_login > last_login
