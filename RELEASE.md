Creating a release
====================

Update release date and version in certgrinder-changelog.rst and certgrinderd-changelog.rst for client & server.

Commit the above changes and push.

Then tag the new release:
    git tag v0.4.0 -a
    <enter something like "Release v0.4.0">
    git push origin v0.4.0

Upload new release to pypi:
    cd client
    python -m build
    twine upload dist/certgrinder*
    cd ../server
    python -m build
    twine upload dist/certgrinderd*

Back to development:
- Update both changelogs

