#!/usr/bin/env python3

import datetime
import sys
import os

sys.path.insert(0, os.path.abspath('..'))
from setup import ALL_DATA

try:
    import sphinx_rtd_theme
except ImportError:
    sphinx_rtd_theme = None

author = ALL_DATA['author']
master_doc = 'index'
project = ALL_DATA['name']
version = release = ALL_DATA['version']

add_module_names = True
copyright = '{0}, {1}'.format(datetime.date.today().year, author)
exclude_patterns = ['_build']
extensions = ['sphinx.ext.viewcode', 'sphinx.ext.autodoc', ]
html_show_sourcelink = True
html_static_path = ['_static']
html_theme = 'sphinx_rtd_theme' if sphinx_rtd_theme else 'alabaster'
html_theme_path = [sphinx_rtd_theme.get_html_theme_path()] if sphinx_rtd_theme else []
htmlhelp_basename = '{0}doc'.format(project)
language = None
latex_documents = [(master_doc, '{0}.tex'.format(project), '{0} Documentation'.format(project), author, 'manual'), ]
latex_elements = dict()
man_pages = [(master_doc, project, '{0} Documentation'.format(project), [author], 1)]
pygments_style = 'sphinx'
source_suffix = '.rst'
templates_path = ['_templates']
texinfo_documents = [(master_doc, project, '{0} Documentation'.format(project), author, project,
                      ALL_DATA['description'], 'Miscellaneous'), ]
todo_include_todos = False

rst_prolog = """
.. |project| replace:: {project}
.. |year| replace:: {year}
.. |author| replace:: {author}
""".format(author=author, project=project, year=datetime.date.today().year)
