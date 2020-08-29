"""Configuration file for the Sphinx documentation builder.

More info at https://www.sphinx-doc.org/en/master/usage/configuration.html
"""
import os
import sys

sys.path.insert(0, os.path.abspath("../client/certgrinder"))
sys.path.insert(0, os.path.abspath("../server/certgrinderd"))
project = "Certgrinder"
copyright = "2020, Thomas Steen Rasmussen"
author = "Thomas Steen Rasmussen"
extensions = [
    "sphinx.ext.autodoc",
    "sphinx_rtd_theme",
    "sphinx.ext.napoleon",
    "sphinxarg.ext",
]
templates_path = ["_templates"]
exclude_patterns = ["_build", "Thumbs.db", ".DS_Store"]
html_static_path = ["_static"]
master_doc = "index"
autodoc_mock_imports = ["yaml", "cryptography", "dns"]
version = "0.14.0-beta2"
html_theme = "sphinx_rtd_theme"
html_theme_options = {"display_version": True}
man_pages = [
    (
        "certgrinder",
        "certgrinder",
        "Manpage for certgrinder",
        ["Thomas Steen Rasmussen"],
        8,
    ),
    (
        "certgrinderd",
        "certgrinderd",
        "Manpage for certgrinderd",
        ["Thomas Steen Rasmussen"],
        8,
    ),
]
manpages_url = "https://certgrinder.readthedocs.io/en/latest/{page}.html"
napoleon_include_init_with_doc = True
