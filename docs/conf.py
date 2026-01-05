# -*- coding: utf-8 -*-
#
# rauc documentation build configuration file, created by
# sphinx-quickstart on Fri Jan 22 16:00:15 2016.

import sys
import os
import subprocess

# If extensions (or modules to document with autodoc) are in another directory,
# add these directories to sys.path here. If the directory is relative to the
# documentation root, use os.path.abspath to make it absolute, like shown here.
#sys.path.insert(0, os.path.abspath('.'))

# -- General configuration ------------------------------------------------

# Add any Sphinx extension module names here, as strings. They can be
# extensions coming with Sphinx (named 'sphinx.ext.*') or your custom
# ones.
extensions = [
    'sphinx.ext.extlinks',
    'sphinx.ext.ifconfig',
    'sphinx_rtd_theme',
]

try:
    import sphinxext.opengraph
    extensions.append('sphinxext.opengraph')
    ogp_site_url = 'https://rauc.readthedocs.io/en/latest/'
    ogp_image = 'https://rauc.readthedocs.io/en/latest/_static/RAUC_Logo_outline.svg'
except ModuleNotFoundError:
    print("not using sphinxext.opengraph")

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

# The suffix of source filenames.
source_suffix = '.rst'

# The master toctree document.
master_doc = 'index'

# General information about the project.
project = u'RAUC'
author = u'Jan Luebbe, Enrico Joerns, the RAUC contributors'
copyright = u'2016-2026, ' + author

# The version info for the project you're documenting, acts as replacement for
# |version| and |release|, also used in various other places throughout the
# built documents.
#
# The short X.Y version.
version = subprocess.check_output(['../build-aux/git-version-gen', '../.tarball-version']).decode()
if version.endswith('-dirty'):
  version = version[:-6]
# The full version, including alpha/beta/rc tags.
release = version

# List of patterns, relative to source directory, that match files and
# directories to ignore when looking for source files.
exclude_patterns = []

# The name of the Pygments (syntax highlighting) style to use.
pygments_style = 'sphinx'

# -- Options for HTML output ----------------------------------------------

# The theme to use for HTML and HTML Help pages.  See the documentation for
# a list of builtin themes.
html_theme = 'sphinx_rtd_theme'

# The name of an image file (relative to this directory) to place at the top
# of the sidebar.
html_logo = 'RAUC_Logo_outline.svg'

# The name of an image file (within the static path) to use as favicon of the
# docs.  This file should be a Windows icon file (.ico) being 16x16 or 32x32
# pixels large.
html_favicon = 'favicon.ico'

# -- Options for LaTeX output ---------------------------------------------

# Grouping the document tree into LaTeX files. List of tuples
# (source start file, target name, title,
#  author, documentclass [howto, manual, or own class]).
latex_documents = [
  ('index', 'rauc.tex', u'RAUC Documentation',
   author, 'manual'),
]

# -- Options for manual page output ---------------------------------------

man_pages = [
  ('man', 'rauc', 'safe and secure updating', '', 1),
]

# -- Options for external links -------------------------------------------

extlinks = {
  'pr': ('https://github.com/rauc/rauc/pull/%s', '#%s'),
}
