Certgrinderd Change Log
========================

This is the changelog for ``certgrinderd``. The latest version of this file
can always be found `on
Github <https://github.com/tykling/certgrinder/blob/master/docs/certgrinderd-changelog.rst>`__

All notable changes to ``certgrinderd`` will be documented in this file.

This project adheres to `Semantic Versioning <http://semver.org/>`__.

v0.15.0 (29-Sep-2020)
---------------------
- No changes


v0.15.0-beta2 (28-Sep-2020)
---------------------------
- No changes


v0.15.0-beta1 (28-Sep-2020)
---------------------------

Added
~~~~~
- Enabled ``check-spelling`` Github action and fixed a bunch of misspelled words all over.

Fixed
~~~~~
- Removed unused ``--rsa-key-size`` arg from certbot command
- Fix wrong requirements line for pre-commit (remove extra equal sign)
- Updated all dependencies in requirements.txt, and switch to pinning deps with == rather than >= so dependabot on github can do its thing


v0.14.2 (13-Sep-2020)
---------------------
- No changes


v0.14.1 (13-Sep-2020)
---------------------

Changed
~~~~~~~
- Change ``intermediate`` to ``issuer`` in the code and tests.

Fixed
~~~~~
- Fix a wrong error message in an assert in ``test_parse_certificate_chain_path()``


v0.14.0 (29-Aug-2020)
---------------------

Changed
~~~~~~~
- Change log message to ``INFO`` when getting a new OCSP response


v0.14.0-beta2 (29-Aug-2020)
---------------------------
- No changes


v0.14.0-beta1 (29-Aug-2020)
---------------------------

Added
~~~~~
- Introduce commands and subcommands (like "get certificate" or "get ocsp")
- Add OCSP response fetching and verifying functionality
- Add requests to requirements (for getting OCSP responses)
- Tests for the new functionality

Changed
~~~~~~~
- Refactor code to fit the commands/subcommand structure
- Log certbot stderr at level ERROR
- Change some default config from None to "" to keep it as str


v0.13.2 (11-Jul-2020)
--------------------

Added
~~~~~
- Manpage to MANIFEST.in to include it in the distribution


v0.13.1 (7-Jul-2020)
--------------------

Changed
~~~~~~~
- Specify python3.7 and 3.8 as classifiers in setup.py


v0.13.0 (7-Jul-2020)
--------------------
- No changes


v0.13.0-rc1 (1-Jul-2020)
------------------------

Added
~~~~~
- Information about $SSH_ORIGINAL_COMMAND to docs

Changed
~~~~~~~
- Show current log-level setting in first log message


v0.13.0-beta2 (29-Jun-2020)
---------------------------

Added
~~~~~

- Dev requirements now has ``sphinx-rtd-theme`` which is the theme used on ReadTheDocs, so ``make html`` in ``docs/`` now produces the same-ish output.
- Dev requirements now include ``sphinx-argparse`` used for generating automatic usage documentation.
- Short command-line options for a bunch of things.
- Manpage certgrinderd.8
- Unittests for a few Certgrinderd() methods

Changed
~~~~~~~
- Move CHANGELOG.md to rst format and into ``docs/``
- Split certbot-command related stuff into new methods get_certbot_command() and run_certbot()
- Split creating the argparse object into a separate function to assist sphinx-argparse
- Test suite now covers 100% of certgrinderd.py

Fixed
~~~~~
- Only try challenge types if we have the needed info (acme-zone for DNS-01, www-root for HTTP-01)


v0.13.0-beta1 (7-May-2020)
---------------------------

-  No changes

v0.13.0-alpha8 (6-May-2020)
----------------------------

Changed
~~~~~~~

-  Changed logformat to prefix messages with certgrinderd: and
   Certgrinderd. instead of nothing and %(name)s, making it more clear
   which messages are from certgrinder and which are from certgrinderd.

v0.13.0-alpha7 (6-May-2020)
----------------------------

-  No changes

v0.13.0-alpha6 (6-May-2020)
----------------------------

Changed
~~~~~~~

-  ``certgrinderd`` now creates a temporary directory for temporary CSR
   and CRT files per run. The directory and contents is at the end of
   each run. If --temp-dir is configured the temporary directory is
   created inside the path specified.

v0.13.0-alpha5 (6-May-2020)
----------------------------

Added
~~~~~

-  -f and -S short options for --config-file and --staging
-  MANIFEST.in file to include sample config and hook scripts

v0.13.0-alpha4 (5-May-2020)
----------------------------

Added
~~~~~

-  New --log-level option to set logging verbosity. Must be one of
   DEBUG, INFO, WARNING, ERROR, CRITICAL, corresponding to the levels in
   the Python logging framework.
-  A lot of new documentation about ``certgrinderd``
-  Command-line options for everything

Changed
~~~~~~~

-  Configuration file and command-line options aligned so everything is
   configurable both places.

v0.13.0-alpha3 (5-May-2020)
----------------------------

Added
~~~~~

-  Add missing PyYAML dependency in setup.py

Changed
~~~~~~~

-  Fix so certgrinderd.conf certbot\_commands with spaces in them work
   as expected

v0.13.0-alpha2 (4-May-2020)
----------------------------

Added
~~~~~

-  Install ``certgrinderd`` binary using entry\_points in setup.py

Changed
~~~~~~~

-  Move CSR loading and testing to class methods in the Certgrinderd
   class
-  Wrap remaining script initialisation in a main() function to support
   entry\_points in setup.py better

v0.13.0-alpha (4-May-2020)
---------------------------

Added
~~~~~

-  Create Python package ``certgrinderd`` for the Certgrinder server,
   publish on pypi
-  Add isort to pre-commit so imports are kept neat
-  Tox and pytest and basic testsuite using Pebble as a mock ACME server
-  Travis and codecov.io integration

Changed
~~~~~~~

-  Move client files into client/ and server files into server/, each
   with their own CHANGELOG.md
-  Rename server from csrgrinder to certgrinderd
-  Rewrite server in Python
