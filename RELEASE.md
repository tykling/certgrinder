Creating a release
====================

First, update the version numbers in needed files (meaning remove -dev):
    sed -i'' "s/0.13.0-beta2-dev/0.13.0-beta2/g" client/setup.py server/setup.py client/certgrinder/certgrinder.py server/certgrinderd/certgrinderd.py docs/conf.py

Then update release date in certgrinder-changelog.rst and certgrinderd-changelog.rst for client & server.

Commit the above changes and push.

Then tag the new release:
    git tag v0.4.0 -a
    <enter something like "Release v0.4.0">
    git push origin v0.4.0

Upload new release to pypi:
    cd client
    python setup.py sdist
    twine upload dist/*
    cd ../server
    python setup.py sdist
    twine upload dist/*

Back to development:
- Bump version and add -dev to version numbers everywhere.
    sed -i'' "s/0.13.0-beta2/0.13.0-beta3-dev/g" client/setup.py server/setup.py client/certgrinder/certgrinder.py server/certgrinderd/certgrinderd.py docs/conf.py
- Update both changelogs

