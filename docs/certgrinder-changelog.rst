Certgrinder Change Log
=======================

This is the changelog for ``certgrinder``. The latest version of this file
can always be found `on
Github <https://github.com/tykling/certgrinder/blob/master/docs/certgrinder-changelog.rst>`__

All notable changes to ``certgrinder`` will be documented in this file.

This project adheres to `Semantic Versioning <http://semver.org/>`__.

v0.13.0-rc1 (1-jul-2020)
-------------------------

Changed
~~~~~~~
- Writing the certificate only (without the intermediate) to ``example.com-certonly.crt`` is new in 0.13, so make the ``check_certificate()`` method checks the chain certificate to make sure upgrading 0.12 to 0.13 doesn't trigger needlessly renewing all existing certs.


v0.13.0-beta2 (29-jun-2020)
---------------------------

Added
~~~~~

- Dev requirements now has ``sphinx-rtd-theme`` which is the theme used on ReadTheDocs, so ``make html`` in ``docs/`` now produces the same-ish output.
- Dev requirements now include ``sphinx-argparse`` used for generating automatic usage documentation.
- Very preliminary support for EC keys in addition to RSA keys.
- More tests
- Better validation of returned certificate and intermediate
- Save intermediate in seperate file, save certificate only in seperate file.
- Documentation for all config settings
- Manpage certgrinder.8
- periodic command to run from cron

Changed
~~~~~~~
- Move CHANGELOG.md to rst format and into ``docs/``
- Rework command-line options, add commands, rework configuration and configfile. This is a backwards incompatible change. Run ``/venv/bin/certgrinder periodic`` from cron, ``certgrinder help`` for more info.
- Configuration is now a combination of command-line options (if any), config file (if any) and default config; in decreasing precedence order. A default setting will be overridden by a config file setting which will be overridden by a command-line setting.
- Update ``certgrinder.conf.dist`` with new options and better comments
- Mark most methods as ``@staticmethod`` or ``@classmethod``, refactor code as needed. This makes the code more reusable and easier to test.
- Split certificate validity tests into seperate methods
- Split parsing of ``certgrinderd`` output into seperate method ``parse_certgrinderd_output()``
- Split argparse stuff (which grew considerably with this change) into seperate ``get_parser()`` func
- Support calling ``certgrinder.main()`` function and ``certgrinder.Certgrinder.grind()`` method with a list of mocked command-line args
- Update existing tests to deal with all the new stuff
- Make pytest logformat look like regular logging
- Split creating the argparse object into a seperate function to assist sphinx-argparse
- Reorder argparse commands and subcommands in alphabetical order
- Re-add -v / --version to show version and exit
- Test suite now covers 100% of certgrinder.py


v0.13.0-beta1 (7-may-2020)
---------------------------

Fixed
~~~~~

-  Made -q / --quiet mode work
-  Made certgrinder always pass ``--log-level LEVEL`` to certgrinderd,
   so the effects of both ``--quiet`` and ``--debug`` are passed to the
   certgrinderd call.

v0.13.0-alpha8 (6-may-2020)
----------------------------

Changed
~~~~~~~

-  Changed logformat to prefix messages with certgrinder: and
   Certgrinder. instead of nothing and %(name)s, making it more clear
   which messages are from certgrinder and which are from certgrinderd
-  Output logging from certgrinderd call

v0.13.0-alpha7 (6-may-2020)
----------------------------

Fixed
~~~~~

-  Old bug where permissions of private key would be fixed to 640 even
   if it was already 640
-  --log-level didn't work without --debug

v0.13.0-alpha6 (6-may-2020)
----------------------------

-  No changes

v0.13.0-alpha5 (6-may-2020)
----------------------------

Added
~~~~~

-  MANIFEST.in file to include certgrinder.conf.dist in installs

Changed
~~~~~~~

-  Default config file is now ~/certgrinder.conf instead of
   ~/certgrinder.yml

v0.13.0-alpha4 (5-may-2020)
----------------------------

Added
~~~~~

-  There is now a --log-level=LEVEL command line argument to set
   loglevel more flexibly. It can be set to one of DEBUG, INFO, WARNING,
   ERROR, or CRITICAL.

Changed
~~~~~~~

-  Config file path should be given with the -f flag
-  Pass --staging and --debug flag to certgrinderd when given to
   certgrinder
-  Prefix syslog messages with "certgrinder" instead of "Certgrinder" to
   match the package name

v0.13.0-alpha3 (5-may-2020)
----------------------------

-  No changes

v0.13.0-alpha2 (4-may-2020)
----------------------------

Added
~~~~~

-  Install ``certgrinder`` binary using entry\_points in setup.py

Changed
~~~~~~~

-  Wrap script initialisation in a main() function to support
   entry\_points in setup.py better

v0.13.0-alpha (4-may-2020)
---------------------------

Added
~~~~~

-  Create Python package ``certgrinder`` for the Certgrinder client,
   publish on pypi
-  Add isort to pre-commit so imports are kept neat
-  Tox and pytest and basic testsuite using Pebble as a mock ACME server
-  Travis and codecov.io integration
-  Add -C argument which simply checks if the certificates are present
   and valid and have more than 30 days validity left. Exit code 0 if
   all is well or exit code 1 if one or more certificates needs
   attention.

Changed
~~~~~~~

-  Move client files into client/ and server files into server/, each
   with their own CHANGELOG.md, in preparation for Python packaging.
-  Reorder commandline arguments alphabetically.
-  Change a few imports to make mypy and isort happy

v0.12.1 (4-jan-2020)
---------------------

Added
~~~~~

-  Add RELEASE.md so I don't forget how to do this

Fixed
~~~~~

-  Fixed release date for v0.12.0 in CHANGELOG.md
-  Add a few type: ignore for some of the cryptography imports and calls
   to make newer mypy happy

Changed
~~~~~~~

-  Update mypy to 0.761 and add to requirements-dev.txt

v0.12.0 (4-jan-2020)
---------------------

Changed
~~~~~~~

-  Support python3 instead of (NOT in addition to) python2
-  Format code with Black
-  Check code with flake8
-  Add type annotations and check code with mypy --strict

Fixed
~~~~~

-  pyyaml load deprecation warning: ./certgrinder.py:54:
   YAMLLoadWarning: calling yaml.load() without Loader=... is
   deprecated, as the default Loader is unsafe. Please read
   https://msg.pyyaml.org/load for full details.

v0.11.0 (25-dec-2018)
----------------------

Added:
~~~~~~

-  Support for setting SSH user: in certgrinder.yml config file.

Changed:
~~~~~~~~

-  Remove OpenSSL dependency for key and X509 operations, use
   cryptography directly instead. This affects any method which deals
   with keys and/or X509.
-  Do not use shell=True for the subprocess.pOpen SSH call.

Removed:
~~~~~~~~

-  Support for selfsigned certificates.

v0.10.2 (5-apr-2018)
---------------------

Added:
~~~~~~

-  Support setting syslog\_facility and syslog\_socket in
   certgrinder.yml (defaults to "user" and "/var/run/log" to maintain
   backwards compat)
-  Warn in the last line when one or more selfsigned certificates has
   been created
-  Show a counter with the number of domainsets being processed

Fixed:
~~~~~~

-  Typo in variable name in logoutput
-  Only log SSH output and exception info when in debug mode
-  Various improvements to logging

v0.10.1 (2-mar-2018)
---------------------

Fixed:
~~~~~~

-  Version number was wrong in certgrinder.py

v0.10.0 (2-mar-2018)
---------------------

Added:
~~~~~~

-  Move from webroot to manual Certbot authenticator, using hook scripts
   manual-auth-hook and manual-cleanup hook
-  Add DNS-01 support in hook scripts. DNS-01 is now the recommended
   challenge type.
-  csrgrinder got a config file
-  Describe new features in README
-  Many improvements to logging and error handling

Fixed:
~~~~~~

-  Language and typos and layout in README

v0.9.5 (16-feb-2018)
---------------------

Fixed:
~~~~~~

-  v0.9.4 had the wrong version number in the .py file.

Added:
~~~~~~

-  -p / --showspki switch to output pin-sha256 pins for the public keys.
   Useful for HPKP or other pinning that uses the same format.

v0.9.4 (17-jan-2018)
---------------------

Fixed:
~~~~~~

-  The showtlsa (-s) and checktlsa (-c) features did not work for
   multiple domain sets

v0.9.3 (17-jan-2018)
---------------------

Fixed:
~~~~~~

-  Custom nameserver functionality was not working due to an error
-  Catch more types of exceptions when looking up DNS results, and exit
   if a serious error occurs.

v0.9.2 (17-jan-2018)
---------------------

Fixed:
~~~~~~

-  Typo in CHANGELOG.md

v0.9.1 (17-jan-2018)
---------------------

Fixed:
~~~~~~

-  Logic for using a custom nameserver with -n / --nameserver was
   inverted.
-  Add example directory structure to README.md

Added:
~~~~~~

-  Show version number in usage and add -v / --version switch to show
   it.
-  Add shebang line to certgrinder.py and make the script executable.

v0.9.0 (16-jan-2018)
---------------------

Added:
~~~~~~

-  This changelog. First numbered release.
