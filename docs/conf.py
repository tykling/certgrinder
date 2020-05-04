# Configuration file for the Sphinx documentation builder.
# https://www.sphinx-doc.org/en/master/usage/configuration.html
import os
import sys

sys.path.insert(0, os.path.abspath("../client/certgrinder"))
sys.path.insert(0, os.path.abspath("../server/certgrinderd"))
project = "Certgrinder"
copyright = "2020, Thomas Steen Rasmussen"
author = "Thomas Steen Rasmussen"
extensions = ["sphinx.ext.autodoc"]
templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]
html_theme = "alabaster"
html_static_path = ["_static"]
master_doc = "index"
