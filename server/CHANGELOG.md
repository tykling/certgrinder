# Change Log
This is the changelog for certgrinderd. The latest version of this file can always be found [on Github](https://github.com/tykling/certgrinder/blob/master/server/CHANGELOG.md)

All notable changes to certgrinderd will be documented in this file.

This project adheres to [Semantic Versioning](http://semver.org/).

## [v0.13.0-alpha3][unreleased]
- Fix so certgrinderd certbot_commands with spaces in them work as expected


## [v0.13.0-alpha2][4-may-2020]
### Added
- Install `certgrinderd` binary using entry_points in setup.py

### Changed
- Move CSR loading and testing to class methods in the Certgrinderd class
- Wrap remaining script initialisation in a main() function to support entry_points in setup.py better


## [v0.13.0-alpha][4-may-2020]
### Added
- Create Python package `certgrinderd` for the Certgrinder server, publish on pypi
- Add isort to pre-commit so imports are kept neat
- Tox and pytest and basic testsuite using Pebble as a mock ACME server
- Travis and codecov.io integration

### Changed
- Move client files into client/ and server files into server/, each with their own CHANGELOG.md
- Rename server from csrgrinder to certgrinderd
- Rewrite server in Python

