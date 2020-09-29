Certgrinder Change Log
=======================

This is the changelog for ``certgrinder``. The latest version of this file
can always be found `on
Github <https://github.com/tykling/certgrinder/blob/master/docs/certgrinder-changelog.rst>`__

All notable changes to ``certgrinder`` will be documented in this file.

This project adheres to `Semantic Versioning <http://semver.org/>`__.

v0.16.0 (unreleased)
--------------------

Fixed
~~~~~
- Show keytype in ``show ocsp`` output


v0.15.1 (29-Sep-2020)
---------------------

Fixed
~~~~~
- Check OCSP response age and get a new one when needed

Added
~~~~~
- Configuration option ``ocsp-renew-threshold-seconds`` - defaults to 86400.


v0.15.0 (29-Sep-2020)
---------------------

Changed
~~~~~~~
- Change output a bit for the ``show tlsa`` subcommand

Fixed
~~~~~
- The ``show tlsa`` command did not work due to type mismatch triggering an assert
- Show keytype in the ``show certificate`` output


v0.15.0-beta2 (28-Sep-2020)
---------------------------

Changed
~~~~~~~
- Check if files exist in the ``show paths`` subcommand.


v0.15.0-beta1 (28-Sep-2020)
---------------------------

Added
~~~~~
- Enabled ECDSA keys and certificates. Default to getting both RSA and ECDSA certificates. Control which keytypes are enabled with the new ``key-type-list`` configuration option. Curve for ECDSA is SECP384R1, this might be made configurable later.
- Added ``show paths`` subcommand to output the various filepaths used.
- Enabled ``check-spelling`` Github action and fixed a bunch of misspelled words all over.

Changed
~~~~~~~
- Changed filenames of keys and certificates. Run the following commands to rename existing RSA files from pre 0.15 installs:

  - The keypair: ``mv example.com.key example.com-keypair.rsa.key``
  - The CSR: ``mv example.com.csr example.com-request.rsa.csr``
  - The certificate chain: ``mv example.com.crt example.com-chain.rsa.crt``
  - The certificate: ``mv example.com-certonly.crt example.com-certificate.rsa.crt``
  - The concat key and chain: ``mv example.com-concat.pem example.com-concat.rsa.pem``
  - The issuer certificate: ``mv example.com-issuer.crt example.com-issuer.rsa.crt``
  - The OCSP response: ``mv example.com.ocsp example.com-response.rsa.ocsp``

  In other words:
  - All files got the keytype (always ``rsa`` for pre-0.15 files) inserted just before the extension, so ``.crt`` becomes ``.rsa.crt`` and ``.key`` becomes ``.rsa.key``.
  - Additionally the keypair files got ``-keypair`` inserted just after the hostname, so ``example.com.rsa.key`` becomes ``example.com-keypair.rsa.key``.
  - Additionally the CSR files got ``-request`` inserted just after the hostname, so ``example.com.rsa.csr`` becomes ``example.com-request.rsa.csr``.
  - Finally the OCSP response got ``-response`` inserted just after the hostname, so ``example.com.rsa.ocsp`` becomes ``example.com-response.rsa.ocsp``.

  This rename must be done for each domainset. If a keypair with the old filename is found Certgrinder will quit with exit code 1 and refuse to run. Use the new ``show paths`` subcommand to figure out what the new filenames should be.

- Prefix certgrinderd output with ``certgrinderd:`` when not in debug mode.
- Updated all dependencies in requirements.txt, and switch to pinning deps with == rather than >= so dependabot on github can do its thing

Fixed
~~~~~
- Fix wrong requirements line for pre-commit (remove extra equal sign)


v0.14.2 (13-Sep-2020)
---------------------

Added
~~~~~
- Make ``show certificate`` output certificate ``not_valid_before`` and ``not_valid_after``

Changed
~~~~~~~
- Rename test ``test_show_certificate()`` to ``test_show_certificate_file_not_found()``


v0.14.1 (13-Sep-2020)
---------------------

Added
~~~~~
- Workaround to get certificate from chain in installations from before foo-certonly.crt was written separately. This makes the "get ocsp" subcommand work even if the current certificate was issued with an older version of certgrinder.

Changed
~~~~~~~
- Rename parse_certgrinderd_certificate_output() to parse_certificate_chain() and clean it up a bit
- Update some log messages and update tests to match
- Change "intermediate" to "issuer" in the code and tests.
- Rename intermediate cert path to example.com-issuer.crt instead of example.com-intermediate.crt. Existing intermediate/issuer certs will be renamed next time "get ocsp" is run, which is done automatically by the "periodic" command.


v0.14.0 (29-Aug-2020)
---------------------

Changed
~~~~~~~
- Update log message when running post-renew hooks


v0.14.0-beta2 (29-Aug-2020)
---------------------------

Added
~~~~~
- Workaround to get intermediate from chain in installations from before foo-intermediate.crt was written separately. This makes the "get ocsp" subcommand work even if the current certificate was issued with an older version of certgrinder.

Changed
~~~~~~~
- Separated the PEM chain splitting logic into a new split_pem_chain method


v0.14.0-beta1 (29-Aug-2020)
---------------------------

Added
~~~~~
- OCSP response support
- Log certgrinderd output at the level certgrinderd logs it at, when possible (otherwise log at WARNING)
- Tests for the new functionality

Changed
~~~~~~~
- Support the new certgrinderd commands and subcommands
- Change short command for --config-file from -f to -c
- Set default certgrinder command to "certgrinderd"
- Use with for opening files a few places to avoid leaving open fds

Fixed
~~~~~
- Changed certgrinder syslog ident from "certgrinderd" to "certgrinder"

v0.13.2 (11-Jul-2020)
---------------------

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

Changed
~~~~~~~
- Test suite now covers 100% of certgrinder.py

Fixed
~~~~~
- Fix broken test client/certgrinder/tests/test_certgrinder.py::test_check_certificate_not_cert
- Fix broken show_certificate() method, and make it output more useful info


v0.13.0-rc1 (1-Jul-2020)
-------------------------

Changed
~~~~~~~
- Writing the certificate only (without the intermediate) to ``example.com-certonly.crt`` is new in 0.13, so make the ``check_certificate()`` method checks the chain certificate to make sure upgrading 0.12 to 0.13 doesn't trigger needlessly renewing all existing certs.


v0.13.0-beta2 (29-Jun-2020)
---------------------------

Added
~~~~~

- Dev requirements now has ``sphinx-rtd-theme`` which is the theme used on ReadTheDocs, so ``make html`` in ``docs/`` now produces the same-ish output.
- Dev requirements now include ``sphinx-argparse`` used for generating automatic usage documentation.
- Very preliminary support for EC keys in addition to RSA keys.
- More tests
- Better validation of returned certificate and intermediate
- Save intermediate in separate file, save certificate only in separate file.
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
- Split certificate validity tests into separate methods
- Split parsing of ``certgrinderd`` output into separate method ``parse_certgrinderd_output()``
- Split argparse stuff (which grew considerably with this change) into separate ``get_parser()`` func
- Support calling ``certgrinder.main()`` function and ``certgrinder.Certgrinder.grind()`` method with a list of mocked command-line args
- Update existing tests to deal with all the new stuff
- Make pytest logformat look like regular logging
- Split creating the argparse object into a separate function to assist sphinx-argparse
- Reorder argparse commands and subcommands in alphabetical order
- Re-add -v / --version to show version and exit
- Test suite now covers 100% of certgrinder.py


v0.13.0-beta1 (7-May-2020)
---------------------------

Fixed
~~~~~

-  Made -q / --quiet mode work
-  Made certgrinder always pass ``--log-level LEVEL`` to certgrinderd,
   so the effects of both ``--quiet`` and ``--debug`` are passed to the
   certgrinderd call.

v0.13.0-alpha8 (6-May-2020)
----------------------------

Changed
~~~~~~~

-  Changed logformat to prefix messages with certgrinder: and
   Certgrinder. instead of nothing and %(name)s, making it more clear
   which messages are from certgrinder and which are from certgrinderd
-  Output logging from certgrinderd call

v0.13.0-alpha7 (6-May-2020)
----------------------------

Fixed
~~~~~

-  Old bug where permissions of private key would be fixed to 640 even
   if it was already 640
-  --log-level didn't work without --debug

v0.13.0-alpha6 (6-May-2020)
----------------------------

-  No changes

v0.13.0-alpha5 (6-May-2020)
----------------------------

Added
~~~~~

-  MANIFEST.in file to include certgrinder.conf.dist in installs

Changed
~~~~~~~

-  Default config file is now ~/certgrinder.conf instead of
   ~/certgrinder.yml

v0.13.0-alpha4 (5-May-2020)
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

v0.13.0-alpha3 (5-May-2020)
----------------------------

-  No changes

v0.13.0-alpha2 (4-May-2020)
----------------------------

Added
~~~~~

-  Install ``certgrinder`` binary using entry\_points in setup.py

Changed
~~~~~~~

-  Wrap script initialisation in a main() function to support
   entry\_points in setup.py better

v0.13.0-alpha (4-May-2020)
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

v0.12.1 (4-Jan-2020)
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

v0.12.0 (4-Jan-2020)
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

v0.11.0 (25-Dec-2018)
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

v0.10.2 (5-Apr-2018)
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

v0.10.1 (2-Mar-2018)
---------------------

Fixed:
~~~~~~

-  Version number was wrong in certgrinder.py

v0.10.0 (2-Mar-2018)
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

v0.9.5 (16-Feb-2018)
---------------------

Fixed:
~~~~~~

-  v0.9.4 had the wrong version number in the .py file.

Added:
~~~~~~

-  -p / --showspki switch to output pin-sha256 pins for the public keys.
   Useful for HPKP or other pinning that uses the same format.

v0.9.4 (17-Jan-2018)
---------------------

Fixed:
~~~~~~

-  The showtlsa (-s) and checktlsa (-c) features did not work for
   multiple domain sets

v0.9.3 (17-Jan-2018)
---------------------

Fixed:
~~~~~~

-  Custom nameserver functionality was not working due to an error
-  Catch more types of exceptions when looking up DNS results, and exit
   if a serious error occurs.

v0.9.2 (17-Jan-2018)
---------------------

Fixed:
~~~~~~

-  Typo in CHANGELOG.md

v0.9.1 (17-Jan-2018)
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

v0.9.0 (16-Jan-2018)
---------------------

Added:
~~~~~~

-  This changelog. First numbered release.
