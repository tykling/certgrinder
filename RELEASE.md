Creating a release
====================

First, update the version numbers in needed files (meaning remove -dev):
* Update release date in CHANGELOG.md for client & server
* Update version in setup.py for client & server
* Update version in README.md for client & server
* Update version in certgrinder.py
* Update version in certgrinderd.py
* Update version numbers in docs

Commit the above and push.

Then tag the new release:
    git tag v0.4.0 -a
    <enter something like "Release v0.4.0">
    git push origin v0.4.0

Upload new release to pypi..

Back to development: Bump version and add -dev to version numbers everywhere.

