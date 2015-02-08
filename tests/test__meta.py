import json
import os
import re
import urllib.request

from pygments import lex
from pygments.lexers import get_lexer_by_name
import pytest


@pytest.mark.skipif('"TRAVIS_REPO_SLUG" not in os.environ')
def test_todo_issue_validator():
    """Verifies that each T.O.D.O is associated with an open GitHub issue."""
    root_directory = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
    assert 'tests' in os.listdir(root_directory)
    generator = (os.path.join(r, s) for r, d, f in os.walk(root_directory) for s in f
                 if s.endswith('.py') and not s.startswith('example_'))
    regex_todo = re.compile(r'^(.*)(?<!\w)(TODO|FIXME)(?!\w)(.*)$', re.IGNORECASE | re.MULTILINE)

    # Find all potential TODOs in Python files. May or may not be in comments/docstrings.
    potential_todos = set()
    for file_path in generator:
        with open(file_path) as f:
            for line in f:
                if regex_todo.search(line):
                    potential_todos.add(file_path)
                    break
    if not potential_todos:
        return

    # Get all open issues.
    repo_slug = os.environ['TRAVIS_REPO_SLUG']
    assert re.match(r'^[a-zA-Z0-9_-]+/[a-zA-Z0-9_-]+$', repo_slug)
    response = urllib.request.urlopen('https://api.github.com/repos/{0}/issues'.format(repo_slug))
    raw_data = response.read().decode('utf-8')
    parsed_data = json.loads(raw_data)
    open_issues = set(['issues/{0:d}'.format(int(i.get('number'))) for i in parsed_data if i.get('state') == 'open'])

    # Perform lexical analysis on the source code and find all docstrings and comments with TODOs.
    todos_with_no_issues = dict()
    for file_path in potential_todos:
        with open(file_path) as f:
            code = f.read(52428800)  # Up to 50 MiB.
        for token, code_piece in lex(code, get_lexer_by_name('Python')):
            if str(token) not in ('Token.Comment', 'Token.Literal.String.Doc'):
                continue
            if not regex_todo.search(code_piece):
                continue
            code_line = ''.join(b for a in regex_todo.findall(code_piece) for b in a)
            has_issue = bool([i for i in open_issues if i in code_line])
            if has_issue:
                continue  # This t.o.d.o has an open issue, skipping.
            # If this is reached, there is a t.o.d.o without an open issue!
            if file_path not in todos_with_no_issues:
                todos_with_no_issues[file_path] = list()
            todos_with_no_issues[file_path].append(code_line)
    assert not todos_with_no_issues


@pytest.mark.skipif('True')
def test_print_hunter():
    """Verifies that there are no print statements in the codebase."""
    root_directory = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', '..'))
    assert 'tests' in os.listdir(root_directory)
    generator = (os.path.join(r, s) for r, d, f in os.walk(root_directory) for s in f
                 if s.endswith('.py') and not s.startswith('example_'))
    regex = re.compile(r'')
