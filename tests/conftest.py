import json
import os
import pathlib
import pwd
import sqlite3
import uuid

import pytest
from mirakuru import TCPExecutor

base_dir = pathlib.Path(__file__).resolve().parent.parent


@pytest.fixture
def sqlite_db_file(tmpdir):
    return str(pathlib.Path(tmpdir) / 'db')


@pytest.fixture
def ipc_result_file(tmpdir):
    return str(pathlib.Path(tmpdir) / 'result.json')


@pytest.fixture
def ipc_return_value_file(tmpdir):
    return str(pathlib.Path(tmpdir) / 'return-value.json')


@pytest.fixture
def get_ipc_result(ipc_result_file):
    def func():
        try:
            with open(ipc_result_file) as fp:
                return json.load(fp)
        except FileNotFoundError:
            return None

    return func


@pytest.fixture
def set_ipc_return_value(ipc_return_value_file):
    def func(value):
        with open(ipc_return_value_file, 'w') as fp:
            return json.dump({'value': value}, fp)

    return func


@pytest.fixture
def knock_server_process(sqlite_db_file, ipc_result_file, ipc_return_value_file):
    cmd = base_dir / 'build' / 'httpknock-server'
    mock_lib = base_dir / 'build' / 'libmocks.so'
    python_path = base_dir / 'tests'

    user_pw = pwd.getpwuid(os.getuid())

    process = TCPExecutor(
        [str(cmd), '--db-path', sqlite_db_file, '--user', user_pw.pw_name],
        envvars={
            'LD_PRELOAD': str(mock_lib),
            'COMM_RESULT_FILE': ipc_result_file,
            'COMM_RETURN_VALUE': ipc_return_value_file,
            'PYTHONPATH': str(python_path),
            'PYTHONUNBUFFERED': '1',
        },
        host='localhost',
        port=8089,
        stdout=None,
    )
    process.start()
    yield
    # make sure we haven't crashed
    assert process.running()
    process.stop()


@pytest.fixture
def knock_server_auth(knock_server_process, sqlite_db_file):
    conn = sqlite3.connect(sqlite_db_file)
    key = str(uuid.uuid4())
    conn.execute("INSERT INTO auth (name, key) VALUES(?, ?)", ('foo', key))
    conn.commit()
    return key
