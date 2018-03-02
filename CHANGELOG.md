# Change Log
This is the changelog for Certgrinder. The latest version of this file can always be found [on Github](https://github.com/tykling/certgrinder/blob/master/CHANGELOG.md)

All notable changes to these roles will be documented in this file.

This project adheres to [Semantic Versioning](http://semver.org/).


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

