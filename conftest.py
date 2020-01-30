import subprocess
import pytest
import shutil
import pathlib
import yaml
import sys


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
