#!/usr/bin/env python

import ast
import atexit
from codecs import open
from distutils.spawn import find_executable
import os
import sys
import subprocess

import setuptools.command.sdist
from setuptools.command.test import test

DESCRIPTION = 'Pure python port of the netlink protocol library suite.'
HERE = os.path.abspath(os.path.dirname(__file__))
KEYWORDS = 'netlink libnl libnl-genl'
NAME = 'libnl'
NAME_FILE = NAME
PACKAGE = True
REQUIRES_INSTALL = []
REQUIRES_TEST = ['pytest-cov']
REQUIRES_PIP = '"' + '" "'.join(set(REQUIRES_INSTALL + REQUIRES_TEST)) + '"'


def get_metadata(main_file):
    """Get metadata about the package/module.

    Positional arguments:
    main_file -- python file path within `HERE` which has __author__ and the others defined as global variables.

    Returns:
    Dictionary to be passed into setuptools.setup().
    """
    with open(os.path.join(HERE, 'README.rst'), encoding='utf-8') as f:
        long_description = f.read(100000)

    with open(os.path.join(HERE, main_file), encoding='utf-8') as f:
        lines = [l.strip() for l in f if l.startswith('__')]
    metadata = ast.literal_eval("{'" + ", '".join([l.replace(' = ', "': ") for l in lines]) + '}')
    __author__, __license__, __version__ = [metadata[k] for k in ('__author__', '__license__', '__version__')]

    everything = dict(version=__version__, long_description=long_description, author=__author__, license=__license__)
    if not all(everything.values()):
        raise ValueError('Failed to obtain metadata from package/module.')

    everything.update(dict(packages=[NAME_FILE]) if PACKAGE else dict(py_modules=[NAME_FILE]))

    return everything


class PyTest(test):
    description = 'Run all tests.'
    TEST_ARGS = ['--cov-report', 'term-missing', '--cov', NAME_FILE, 'tests']

    def finalize_options(self):
        test.finalize_options(self)
        setattr(self, 'test_args', self.TEST_ARGS)
        setattr(self, 'test_suite', True)

    def run_tests(self):
        # Import here, cause outside the eggs aren't loaded.
        pytest = __import__('pytest')
        err_no = pytest.main(self.test_args)
        sys.exit(err_no)


class PyTestPdb(PyTest):
    description = 'Run all tests, drops to ipdb upon unhandled exception.'
    TEST_ARGS = ['--ipdb', 'tests']


class PyTestCovWeb(PyTest):
    description = 'Generates HTML report on test coverage.'
    TEST_ARGS = ['--cov-report', 'html', '--cov', NAME_FILE, 'tests']

    def run_tests(self):
        if find_executable('open'):
            atexit.register(lambda: subprocess.call(['open', os.path.join(HERE, 'htmlcov', 'index.html')]))
        PyTest.run_tests(self)


class CmdStyle(setuptools.Command):
    user_options = []
    CMD_ARGS = ['flake8', '--max-line-length', '120', '--statistics', NAME_FILE + ('' if PACKAGE else '.py')]

    def initialize_options(self):
        pass

    def finalize_options(self):
        pass

    def run(self):
        subprocess.call(self.CMD_ARGS)


class CmdLint(CmdStyle):
    description = 'Run pylint on entire project.'
    CMD_ARGS = ['pylint', '--max-line-length', '120', NAME_FILE + ('' if PACKAGE else '.py')]


ALL_DATA = dict(
    name=NAME,
    description=DESCRIPTION,
    url='https://github.com/Robpol86/{0}'.format(NAME),
    author_email='robpol86@gmail.com',

    classifiers=[
        'Development Status :: 1 - Planning',
        'Intended Audience :: Developers',
        'License :: OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)',
        'Operating System :: POSIX :: Linux',
        'Programming Language :: Python :: 3.4',
        'Topic :: Software Development :: Libraries',
        'Topic :: System :: Networking',
        'Topic :: System :: Operating System Kernels :: Linux',
    ],

    keywords=KEYWORDS,
    zip_safe=True,

    install_requires=REQUIRES_INSTALL,
    tests_require=REQUIRES_TEST,
    cmdclass=dict(test=PyTest, testpdb=PyTestPdb, testcovweb=PyTestCovWeb, style=CmdStyle, lint=CmdLint),

    # Pass the rest from get_metadata().
    **get_metadata(os.path.join(NAME_FILE + ('/__init__.py' if PACKAGE else '.py')))
)


if __name__ == '__main__':
    setuptools.setup(**ALL_DATA)
