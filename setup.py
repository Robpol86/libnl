#!/usr/bin/env python
"""Setup script for the project."""

import codecs
import os
import re

import setuptools

_PACKAGES = lambda: [os.path.join(r, s) for r, d, _ in os.walk(NAME_FILE) for s in d if s != '__pycache__']
_VERSION_RE = re.compile(r"^__(version|author|license)__ = '([\w\.@]+)'$", re.MULTILINE)

CLASSIFIERS = (
    'Development Status :: 4 - Beta',
    'Intended Audience :: Developers',
    'License :: OSI Approved :: GNU Lesser General Public License v2 or later (LGPLv2+)',
    'Operating System :: POSIX :: Linux',
    'Programming Language :: Python :: 2.6',
    'Programming Language :: Python :: 2.7',
    'Programming Language :: Python :: 3.3',
    'Programming Language :: Python :: 3.4',
    'Programming Language :: Python :: Implementation :: PyPy',
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
REQUIRES_INSTALL = []
REQUIRES_TEST = ['docopt', 'pygments', 'pytest-cov', 'terminaltables']
REQUIRES_ALL = REQUIRES_INSTALL + REQUIRES_TEST
VERSION_FILE = os.path.join(NAME_FILE, '__init__.py') if PACKAGE else '{0}.py'.format(NAME_FILE)


def _safe_read(path, length):
    """Read file contents."""
    if not os.path.exists(os.path.join(HERE, path)):
        return ''
    file_handle = codecs.open(os.path.join(HERE, path), encoding='utf-8')
    contents = file_handle.read(length)
    file_handle.close()
    return contents


ALL_DATA = dict(
    author_email='robpol86@gmail.com',
    classifiers=CLASSIFIERS,
    description=DESCRIPTION,
    install_requires=REQUIRES_INSTALL,
    keywords=KEYWORDS,
    long_description=_safe_read('README.rst', 15000),
    name=NAME,
    requires=REQUIRES_INSTALL,
    tests_require=REQUIRES_TEST,
    url='https://github.com/Robpol86/{0}'.format(NAME),
    zip_safe=True,
)


# noinspection PyTypeChecker
ALL_DATA.update(dict(_VERSION_RE.findall(_safe_read(VERSION_FILE, 1500).replace('\r\n', '\n'))))
ALL_DATA.update(dict(py_modules=[NAME_FILE]) if not PACKAGE else dict(packages=[NAME_FILE] + _PACKAGES()))


if __name__ == '__main__':
    if not all((ALL_DATA['author'], ALL_DATA['license'], ALL_DATA['version'])):
        raise ValueError('Failed to obtain metadata from package/module.')
    setuptools.setup(**ALL_DATA)
