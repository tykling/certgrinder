import subprocess
import pytest
import shutil
import pathlib
import yaml
import sys
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_public_key


@pytest.fixture(scope="session", autouse=True)
def pebble_server():
    """
    get the pebble sources, and build the binary, and run it
    """
    print("Begginning setup")
    print("checking to see if we have Go available...")
    if not shutil.which("go"):
        print("go binary not found in $PATH, cannot build pebble, bailing out")
        return False

    print("Getting pebble sources ...")
    proc = subprocess.run(
        args=[shutil.which("go"), "get", "-u", "github.com/letsencrypt/pebble/..."],
        env={
            "GOPATH": pathlib.Path.home() / "go",
            "PATH": str(pathlib.Path(shutil.which("git")).parent),
        },
    )
    assert proc.returncode == 0

    print("Building pebble...")
    proc = subprocess.run(
        args=[shutil.which("go"), "install", "./..."],
        env={"GOPATH": pathlib.Path.home() / "go"},
        cwd=pathlib.Path.home() / "go/src/github.com/letsencrypt/pebble",
    )
    assert proc.returncode == 0

    print("Running pebble server...")
    proc = subprocess.Popen(
        args=[
            pathlib.Path.home() / "go/bin/pebble",
            "-config",
            pathlib.Path.home()
            / "go/src/github.com/letsencrypt/pebble/test/config/pebble-config.json",
        ],
        env={"PEBBLE_VA_ALWAYS_VALID": "1"},
        cwd=pathlib.Path.home() / "go/src/github.com/letsencrypt/pebble",
    )
    # get Pebble startup output
    # proc.communicate()

    if proc.returncode is not None:
        pytest.fail(
            "Something is fucky, pebble exited with returncode {proc.returncode}"
        )

    print("Setup finished - pebble is running!")

    yield

    # get Pebble output
    # proc.communicate()

    print("Beginning teardown")
    print("Stopping pebble server...")
    proc.terminate()
    print("Teardown finished!")


@pytest.fixture(scope="session", autouse=True)
def certgrinderd_configfile(tmp_path_factory):
    """
    Write a certgrinderd.yml file for this test run
    """
    confpath = tmp_path_factory.mktemp("conf") / "certgrinderd.yml"
    conf = {
        "acmeserver_url": "https://127.0.0.1:14000/dir",
        "verify_acmeserver_cert": False,
        "authhook": "echo 'authhook faked OK!'",
        "cleanuphook": "echo 'cleanuphook faked OK!'",
        "certbot_command": str(pathlib.Path(sys.executable).parent / "certbot"),
        "certbot_configdir": str(tmp_path_factory.mktemp("certbot") / "configdir"),
        "certbot_workdir": str(tmp_path_factory.mktemp("certbot") / "workdir"),
        "certbot_logsdir": str(tmp_path_factory.mktemp("certbot") / "logsdir"),
        "acme_email": "certgrindertest@invalid",
        "syslog_socket": None,
        "syslog_facility": None,
    }
    with open(confpath, "w") as f:
        yaml.dump(conf, f)
    # return path to the config
    return confpath


@pytest.fixture(scope="session", autouse=True)
def certgrinder_configfile(tmpdir_factory, certgrinderd_configfile):
    """
    Write a certgrinder.yml file for this test run
    """
    confpath = tmpdir_factory.mktemp("conf") / "certgrinder.yml"
    conf = {
        "path": str(tmpdir_factory.mktemp("certificates")),
        "domainlist": ["example.com,www.example.com", "example.net"],
        "certgrinderd": f"server/certgrinderd/certgrinderd.py {certgrinderd_configfile}",
    }
    with open(confpath, "w") as f:
        yaml.dump(conf, f)
    # return path to the config
    return confpath


@pytest.fixture(scope="session", autouse=True)
def known_public_key(tmpdir_factory, certgrinderd_configfile):
    pem_public_key = """
-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAtzhbcozNYjS1ee55GDKd
qYjesYuD6nxFQiuCgfU2gqxXyTrEKOs7/yFpJmYsxp00/C2O5EZzych++Nzf/ek/
xfSDg0Rl8HU3ZpHaRvsVe2jj1Y4WtaXA+vAmpuqtwf1H5VwLLphmnNE6mkKvxxgP
iHaeQJpGApzOD+MYSmb/Ohq7uEjPcGTvKZJGykIXXvvTD6KiQ3sZ78nae8r6dNWD
2oOXuEs0kufAhKoxtJzzzeGmYfCxEvJnbxumyeuetC6xBO5/DAhZ2fDDxYIWArfW
KMLmIZXSF0zqq6onlNrroOt8FlorbqFGzqygjsBTTdv3QUnGlLbQPsjKyCUSFYU7
QXFYjFs9i1u0ucmWD3W1QKYXWfREdGSKz5gQq6ZVGTeQMGOXae7MeC7x0LgelWg5
sjt3p1OGhiW2ZI5eCs/TH0Dtt7JstdnquR/s3rnv71dS9PXpqSyHudIHMtE/6Qd6
vVdnBldWwBtSZHIrsnQK9aHuKmCwjFgUyM7YdNvOLwNKNkvFlHO8tltkY94+ZlfG
soewIFCgBddMRhdzXCezJPrgBEkbtkYwKUC7cjn9yZfz9ewnymg/F0L1wnl4CzLO
M9JPoRtj7TkLrEF8wSBv/0n7ziA/nDHZqvoQb8cWlyPwC8alngFCeQE1wTHTi/VJ
GD7OUrxoP9QtBwV7q7YlnoECAwEAAQ==
-----END PUBLIC KEY-----
"""
    return load_pem_public_key(
        pem_public_key.encode("ascii"), backend=default_backend()
    )
