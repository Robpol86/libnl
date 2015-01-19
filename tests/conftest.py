import os
import json

import pytest


@pytest.fixture(scope='session')
def correct_answers():
    json_file_path = os.path.join(os.path.dirname(__file__), 'correct_answers.json')
    if not os.path.exists(json_file_path):
        raise RuntimeError('Missing correct_answers.json! Compile and run correct_answers.c, redirect stdout.')
    with open(json_file_path) as f:
        contents = f.read(10000)
    parsed = json.loads(contents)
    return parsed
