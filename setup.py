#!/usr/bin/env python

import atexit
import os
import re
import subprocess
import sys
from codecs import open
from distutils.spawn import find_executable

import setuptools.command.sdist
from setuptools.command.test import test

_JOIN = lambda *p: os.path.join(HERE, *p)
_PACKAGES = lambda: [os.path.join(r, s) for r, d, _ in os.walk(NAME_FILE) for s in d if s != '__pycache__']
_REQUIRES = lambda p: [i for i in open(_JOIN(p), encoding='utf-8') if i[0] != '-'] if os.path.exists(_JOIN(p)) else []
_SAFE_READ = lambda f, l: open(_JOIN(f), encoding='utf-8').read(l) if os.path.exists(_JOIN(f)) else ''
_VERSION_RE = re.compile(r"^__(version|author|license)__ = '([\w\.@]+)'$", re.MULTILINE)

CLASSIFIERS = (
    'Development Status :: 4 - Beta',
    'Intended Audience :: Developers',
    'License :: OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)',
    'Operating System :: POSIX :: Linux',
    'Programming Language :: Python :: 2.7',
    'Programming Language :: Python :: 3.3',
    'Programming Language :: Python :: 3.4',
    'Topic :: Software Development :: Libraries',
    'Topic :: System :: Networking',
    'Topic :: System :: Operating System Kernels :: Linux',
)
DESCRIPTION = 'Pure Python port of the Netlink protocol library suite.'
HERE = os.path.abspath(os.path.dirname(__file__))
KEYWORDS = 'netlink libnl libnl-genl nl80211'
NAME = 'libnl'
NAME_FILE = NAME
PACKAGE = True
VERSION_FILE = os.path.join(NAME_FILE, '__init__.py') if PACKAGE else '{0}.py'.format(NAME_FILE)


class PyTest(test):
    description = 'Run all tests.'
    user_options = []
    CMD = 'test'
    TEST_ARGS = ['--cov-report', 'term-missing', '--cov', NAME_FILE, 'tests']

    def finalize_options(self):
        overflow_args = sys.argv[sys.argv.index(self.CMD) + 1:]
        test.finalize_options(self)
        setattr(self, 'test_args', self.TEST_ARGS + overflow_args)
        setattr(self, 'test_suite', True)

    def run_tests(self):
        # Import here, cause outside the eggs aren't loaded.
        pytest = __import__('pytest')
        err_no = pytest.main(self.test_args)
        sys.exit(err_no)


class PyTestPdb(PyTest):
    ipdb = 'ipdb' if sys.version_info[:2] > (2, 6) else 'pdb'
    description = 'Run all tests, drops to {0} upon unhandled exception.'.format(ipdb)
    CMD = 'testpdb'
    TEST_ARGS = ['--{0}'.format(ipdb), 'tests']


class PyTestCovWeb(PyTest):
    description = 'Generates HTML report on test coverage.'
    CMD = 'testcovweb'
    TEST_ARGS = ['--cov-report', 'html', '--cov', NAME_FILE, 'tests']

    def run_tests(self):
        if find_executable('open'):
            atexit.register(lambda: subprocess.call(['open', _JOIN('htmlcov', 'index.html')]))
        PyTest.run_tests(self)


ALL_DATA = dict(
    author_email='robpol86@gmail.com',
    classifiers=CLASSIFIERS,
    cmdclass={PyTest.CMD: PyTest, PyTestPdb.CMD: PyTestPdb, PyTestCovWeb.CMD: PyTestCovWeb},
    description=DESCRIPTION,
    install_requires=_REQUIRES('requirements.txt'),
    keywords=KEYWORDS,
    long_description=_SAFE_READ('README.rst', 15000),
    name=NAME,
    tests_require=_REQUIRES('requirements-test.txt'),
    url='https://github.com/Robpol86/{0}'.format(NAME),
    zip_safe=True,
)


# noinspection PyTypeChecker
ALL_DATA.update(dict(_VERSION_RE.findall(_SAFE_READ(VERSION_FILE, 1500).replace('\r\n', '\n'))))
ALL_DATA.update(dict(py_modules=[NAME_FILE]) if not PACKAGE else dict(packages=[NAME_FILE] + _PACKAGES()))


if __name__ == '__main__':
    if not all((ALL_DATA['author'], ALL_DATA['license'], ALL_DATA['version'])):
        raise ValueError('Failed to obtain metadata from package/module.')
    setuptools.setup(**ALL_DATA)
