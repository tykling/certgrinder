# Change Log
This is the changelog for Certgrinder. The latest version of this file can always be found [on Github](https://github.com/tykling/certgrinder/blob/master/CHANGELOG.md)

All notable changes to Certgrinder will be documented in this file.

This project adheres to [Semantic Versioning](http://semver.org/).

## [v0.12.1][4-jan-2020]
### Added
- Add RELEASE.md so I don't forget how to do this

### Fixed
- Fixed release date for v0.12.0 in CHANGELOG.md
- Add a few type: ignore for some of the cryptography imports and calls to make newer mypy happy

### Changed
- Update mypy to 0.761 and add to requirements-dev.txt


## [v0.12.0][4-jan-2020]
### Changed
- Support python3 instead of (NOT in addition to) python2
- Format code with Black
- Check code with flake8
- Add type annotations and check code with mypy --strict

### Fixed
- pyyaml load deprecation warning: ./certgrinder.py:54: YAMLLoadWarning: calling yaml.load() without Loader=... is deprecated, as the default Loader is unsafe. Please read https://msg.pyyaml.org/load for full details.


## [v0.11.0][25-dec-2018]
### Added:
- Support for setting SSH user: in certgrinder.yml config file.

### Changed:
- Remove OpenSSL dependency for key and X509 operations, use cryptography directly instead. This affects any method which deals with keys and/or X509.
- Do not use shell=True for the subprocess.pOpen SSH call.

### Removed:
- Support for selfsigned certificates.


## [v0.10.2][5-apr-2018]
### Added:
- Support setting syslog_facility and syslog_socket in certgrinder.yml (defaults to "user" and "/var/run/log" to maintain backwards compat)
- Warn in the last line when one or more selfsigned certificates has been created
- Show a counter with the number of domainsets being processed

### Fixed:
- Typo in variable name in logoutput
- Only log SSH output and exception info when in debug mode
- Various improvements to logging


## [v0.10.1][2-mar-2018]
### Fixed:
- Version number was wrong in certgrinder.py

## [v0.10.0][2-mar-2018]
### Added:
- Move from webroot to manual Certbot authenticator, using hook scripts manual-auth-hook and manual-cleanup hook
- Add DNS-01 support in hook scripts. DNS-01 is now the recommended challenge type.
- csrgrinder got a config file
- Describe new features in README
- Many improvements to logging and error handling

### Fixed:
- Language and typos and layout in README

## [v0.9.5][16-feb-2018]
### Fixed:
- v0.9.4 had the wrong version number in the .py file.

### Added:
- -p / --showspki switch to output pin-sha256 pins for the public keys. Useful for HPKP or other pinning that uses the same format.


## [v0.9.4][17-jan-2018]
### Fixed:
- The showtlsa (-s) and checktlsa (-c) features did not work for multiple domain sets


## [v0.9.3][17-jan-2018]
### Fixed:
- Custom nameserver functionality was not working due to an error
- Catch more types of exceptions when looking up DNS results, and exit if a serious error occurs.


## [v0.9.2][17-jan-2018]
### Fixed:
- Typo in CHANGELOG.md


## [v0.9.1][17-jan-2018]
### Fixed:
- Logic for using a custom nameserver with -n / --nameserver was inverted.
- Add example directory structure to README.md

### Added:
- Show version number in usage and add -v / --version switch to show it. 
- Add shebang line to certgrinder.py and make the script executable.


## [v0.9.0][16-jan-2018]
### Added:
- This changelog. First numbered release.

