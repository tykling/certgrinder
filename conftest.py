"""pytest configuration file for Certgrinder project."""
import pathlib
import shutil
import subprocess
import sys

import pytest
import yaml
from cryptography.hazmat import primitives
from cryptography.hazmat.backends import default_backend


@pytest.fixture(scope="session")
def pebble_server():
    """Get the pebble sources, and build the binary, and run it."""
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


@pytest.fixture(scope="session")
def certgrinderd_configfile(tmp_path_factory):
    """Write a certgrinderd.yml file for this test run."""
    confpath = tmp_path_factory.mktemp("conf") / "certgrinderd.yml"
    conf = {
        "acme-server-url": "https://127.0.0.1:14000/dir",
        "skip-acme-server-cert-verify": True,
        "auth-hook": "echo 'authhook faked OK!'",
        "cleanup-hook": "echo 'cleanuphook faked OK!'",
        "certbot-command": str(pathlib.Path(sys.executable).parent / "certbot"),
        "certbot-config-dir": str(tmp_path_factory.mktemp("certbot") / "configdir"),
        "certbot-work-dir": str(tmp_path_factory.mktemp("certbot") / "workdir"),
        "certbot-logs-dir": str(tmp_path_factory.mktemp("certbot") / "logsdir"),
        "acme-email": "certgrindertest@invalid",
        "web-root": str(tmp_path_factory.mktemp("certbot") / "webroot"),
    }
    with open(confpath, "w") as f:
        yaml.dump(conf, f)
    # return path to the config
    return confpath


@pytest.fixture(scope="session")
def known_public_key(tmpdir_factory, certgrinderd_configfile):
    """Define, load and return a known public key."""
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
    return primitives.serialization.load_pem_public_key(
        pem_public_key.encode("ascii"), backend=default_backend()
    )


@pytest.fixture(scope="session")
def known_csr():
    """A CSR for example.com,www.example.com."""
    pem_csr = """
-----BEGIN CERTIFICATE REQUEST-----
MIIElTCCAn0CAQAwFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wggIiMA0GCSqGSIb3
DQEBAQUAA4ICDwAwggIKAoICAQCfJPJMw+x8Zc/ALgByAvxXITMllCDE18zApZL9
LG1xDB7F0hIRoaj66NeBv3yiq3aWYoRjNxnm9hLnQdNytU3ZONRJJNP+fV+bkIYO
y7GIYEnMBVYyJlAlWQiaW8mBiQcD1AAo49EJh+zOfOdJPsDaPOEd++UNfv0/wST7
c6e9vxCFK2KNN/OF4+SIlDBMvfQ8DC1ZWwqJcmD1b3ZCzWB8kO+ItKtjnuggV4lA
WYO+LdwAXUUgo+HWodhmvY7dRqDtOnZACTwNqerpMlMvu5HphhdZRXxSeGA8cSCS
c++aV8K4i2LZD4mEO0bkr0JRB1FV8XnPDYIZAeaTUVXy3HlaTVUpYp8ffH4Kid1v
2MMwE49nH38GN3LG/bzTsSAqy9ciZ6KiFERVmudcVjPc6OBSH45ReTj7Pq4BkgJ+
wgbKPXqaFjm9ICezYmRytR1lC/LX7BjKn6hFHBfGEm2GmW+DmXi6lJoq0+n0PVCE
ijVMwZhtK909oZBX3gsgfCLhR6eE9g0blV0EORXYWPm7rZKEUtT1IsKxMdKX3T2u
vwckxyc4CaWCr/xMW8gErtP4ZepsMqdzJRhF1gTAKS4ppBxlW7fTM5Pbkbg8rEXQ
vKmZsWlA40rgbDKxB18AgiUKoHs3oKsyHckOXGrSP7fUKJyFpFgI01CvGzvXTKmo
AYlJWQIDAQABoDowOAYJKoZIhvcNAQkOMSswKTAnBgNVHREEIDAeggtleGFtcGxl
LmNvbYIPd3d3LmV4YW1wbGUuY29tMA0GCSqGSIb3DQEBCwUAA4ICAQCTkzOjiqAd
SWrzOO/Ik2EHzORK3F530mm6CNMymICTEbvE4CImuWHfc12mmEcM1EVSMOkZ912U
lmxeyqVKCpZJkA8SZScm1H2mwmAaC8f1waUKI9lRpZ8GH42bkzYDUBzRpYOWa2df
+oqXvA9c48wAswLEceXA82CBXxUjLQKpnkUgVngIhq9wqRoBf/SrkiUN7E4YkYbx
BN4OO9kdfqLO0uvsaYSLOX1Zzd42eNqAdDqUDha1By1YSd73VpN+konUDZyV7I3e
9OsJBil9okrlEHivxKeTu6BhQwRKL7eMtimvF8Srr+T3aW6zjQ1BpwwznX66lFju
/P06orgJcRi3TjJMvNk4OULh4rkZN1VcdkcK+nVFBuoTIR8ptbkn/BPYBk2hwRFM
UV5W+f0PMxxSFcJPZnw/idippDHRbOZA4tH7QRpKROErKoBJTNIz9YilGHDpCdNh
OolfADAayHBZrHKLPRlAyxfEYdxrXhUtZXS5FekExzHB/K/wqREuCJrjrW5VdoFl
G2egTXinDS3AboH6SYoMWfHLpW4HBdNVXF1P8Oovf+kPL6Bo/9O6A+77Ca1wMWxM
d8KZWLeP8a1J3pggniM6BdN03Zw5+n8+u/v90TuumQmqQo0uHRzm2H+GCDVYnd/r
L37QA7qQ9foiMk/wJdtkYNss1xD7dW+biQ==
-----END CERTIFICATE REQUEST-----
"""
    return pem_csr


@pytest.fixture(scope="session")
def csr_with_two_cn():
    """An invalid CSR for example.com,www.example.com with two CommonName attributes."""
    two_cn_csr = """
-----BEGIN CERTIFICATE REQUEST-----
MIIEqzCCApMCAQAwLDEUMBIGA1UEAwwLZXhhbXBsZS5jb20xFDASBgNVBAMMC2V4
YW1wbGUuY29tMIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAy/boiWbI
YAXbgyD4sfFYOk50Y8S+hnPQHPLOdfByOc1F3uL1CwFlQmfYlxWktf/N5eJ5CYfu
ebW2yyWNfJYub58GdDfLPtGLBwQHbbxXtJscXkolTjRVW0oRAV0AGobtYEAmFlGd
rKDBpEFwtwJq4yqn/TyDEBGrP6UadblX6tR/5zYFFCtuW0bWFbOTKCEPzpw37qyG
tD1SfI89OvleYP3kITHV/Wdto9hj+07FIfv9Zw7b3rvUGmjtA3CunIxXs1lQvD80
uY/DH2CVvG1RNKIyp/kxF1wpJiYB3J8evdgOqi0d1mmvuqqPr8ho+30yaiwK2tIG
3YDLXUajRxWrWfimZupKnUeysaO8kZVw9aw1Ju+p8SJRdAWQ69ccdcr1EzCw0jvS
qKWeI+uzx9thc0dJiGc98SVTrov087k1tTfNa3eycu9N/GOj9YCt3NshDYRBToUl
4GNcZJh/VHMBm6caIgE+BtZcMMJZPIn+/f1KiLcQn+4yTSDyNp0yjpz/xL/+fCpt
WYNgKeIcNlCU6t/+0Re4bhYDrWO4qDBnTR3PyhKZeiHMpna8PF7SySrqNie7MafA
+J9iSXiEPmMu2AYYV/ayHKikbSgK0lmCTW0QGidmRvq7Cr5+/K0M9DkgW07uMoT7
XJcBU1FWEOyQnx4j4zPs/Mobe6WBoaCf85MCAwEAAaA6MDgGCSqGSIb3DQEJDjEr
MCkwJwYDVR0RBCAwHoILZXhhbXBsZS5jb22CD3d3dy5leGFtcGxlLmNvbTANBgkq
hkiG9w0BAQsFAAOCAgEAXoE5B/3ESTA3KlquCB1rt56koT9VHIZ/xVZP+Lp1awZj
AP5niPV4KM6m2cml4syF2b7B4B2j7rDNvXzVg8Q+jts2Xhrc0f33Vw81N23vSTcR
lYviCIR3RRs/DAtBu1ennHKMAHK77VUlxzDWeB1XbSl7RK9X7ch+bB/QMocnM1id
fc3eMleHJu7HU2UiywNO/2NqPPumOsyYgdcW742aIMcgP6wi6iiZr37dXEZNnHv1
T/quyqsMIMt7yL8+say+7LRfOp8OM/HAAZj5vtN+tPGggi4Otn1Ev/ZFsXiNw4Dh
+YnVePtfk1gHbHQvf5S5inFIXBVdRDpWXJrRtMbV04q9mUVAd+457mzea5Wfhxb+
dG05qOzy5xzx0E+utZ/0+Z35Rzah1QofSOwPQMVWc3vfFoggNkKPD4sIJXn+zWnO
KQ0gh3AL88LfZWGDEzx0/fXeX0CkC2jDT/JkIp59tFIW6U0oFpgRSZnEwMwa1Erz
s7xh1tTkn6U6S9PThuSiB0BZLKcFShmaOFEnB9iSZk3hqBzLUOeHIQ/n8169Dl+e
E/z2xWIHXPvCirPOUmflrfdT9loHvYW9vD1z00tKK/wPQRG2C5LGOfFLw/Kq9wBu
ynp0GOksYz7y2xIUBhtNyye8P4LbsYlixLAmL0vcWXmqt34j9rsTUyBGvIa+NkU=
-----END CERTIFICATE REQUEST-----"""
    return two_cn_csr


@pytest.fixture
def certgrinderd_env(monkeypatch):
    """Whip up a fake CERTGRINDERD_DOMAINSETS environment for certgrinderd."""
    monkeypatch.setenv(
        "CERTGRINDERD_DOMAINSETS", "example.com,www.example.com;example.net"
    )
