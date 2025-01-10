Creating a release
====================

Update release date and version in certgrinder-changelog.rst and certgrinderd-changelog.rst for client & server.

Commit the above changes and push.

Then tag the new release:
    git tag v0.4.0 -a
    <enter something like "Release v0.4.0">
    git push origin v0.4.0

Back to development:
- Update both changelogs
