import json
import os


def get_return_value():
    try:
        with open(os.getenv('COMM_RETURN_VALUE')) as fp:
            return json.load(fp)['value']
    except FileNotFoundError:
        return None


def mock_nft_call():
    result_file = os.getenv('COMM_RESULT_FILE')
    with open(result_file, 'w') as fp:
        json.dump({'status': 'ok'}, fp)
    return get_return_value()
