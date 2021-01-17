"""pytest configuration file for Certgrinder project."""
import datetime
import json
import pathlib
import shutil
import subprocess
import sys
import time

import pytest
import requests
import yaml
from cryptography import x509
from cryptography.hazmat import primitives
from cryptography.hazmat.backends import default_backend


@pytest.fixture(scope="session")
def pebble_server():
    """Get the pebble sources, and build the binary, and run it."""
    print("Making sure we have Go and Git...")
    assert shutil.which("go") is not None, "Go is required to run the testsuite (for building Pebble)"
    assert shutil.which("git") is not None, "Git is required to run the testsuite (for getting Pebble sources)"
    print("Begginning setup")
    print("Getting pebble sources ...")
    proc = subprocess.run(
        args=[shutil.which("go"), "get", "-u", "github.com/letsencrypt/pebble/..."],
        env={
            "GOPATH": pathlib.Path.home() / "go",
            "PATH": "/bin:/usr/bin:/usr/local/bin:"
            + str(pathlib.Path(shutil.which("git")).parent),
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

    print("Patching pebble config file...")
    pebbleconfig = (
        pathlib.Path.home()
        / "go/src/github.com/letsencrypt/pebble/test/config/pebble-config.json"
    )
    with open(pebbleconfig, "r") as f:
        conf = json.loads(f.read())
    conf["pebble"].update({"ocspResponderURL": "http://127.0.0.1:8080"})
    with open(pebbleconfig, "w") as f:
        f.write(json.dumps(conf))

    print("Running pebble server...")
    proc = subprocess.Popen(
        args=[pathlib.Path.home() / "go/bin/pebble", "-config", pebbleconfig],
        env={"PEBBLE_VA_ALWAYS_VALID": "1", "PEBBLE_WFE_NONCEREJECT": "0"},
        cwd=pathlib.Path.home() / "go/src/github.com/letsencrypt/pebble",
    )

    time.sleep(2)
    print("Setup finished - pebble is running!")

    # end buildup
    yield
    # begin teardown

    print("Beginning teardown")
    print("Stopping pebble server...")
    proc.terminate()
    print("Teardown finished!")


@pytest.fixture(scope="session")
def pebble_issuer(tmp_path_factory):
    """Download issuer cert and key from pebble and write it to a temp file."""
    certpath = tmp_path_factory.mktemp("pebble") / "pebble-issuer.crt"
    r = requests.get(
        "https://127.0.0.1:15000/intermediates/0",
        verify=pathlib.Path.home()
        / "go/src/github.com/letsencrypt/pebble/test/certs/pebble.minica.pem",
    )
    with open(certpath, "wb") as f:
        f.write(r.content)

    keypath = tmp_path_factory.mktemp("pebble") / "pebble-issuer.key"
    r = requests.get(
        "https://localhost:15000/intermediate-keys/0",
        verify=pathlib.Path.home()
        / "go/src/github.com/letsencrypt/pebble/test/certs/pebble.minica.pem",
    )
    with open(keypath, "wb") as f:
        f.write(r.content)

    # return both paths
    return keypath, certpath


@pytest.fixture(scope="function")
def ocsp_ca_index_file(tmp_path_factory):
    """Return path to the CA index file to use for testing."""
    indexpath = tmp_path_factory.mktemp("pebble") / "pebble-ocsp-index.ca"
    print(f"Path to CA index for this test session is {indexpath}")
    with open(indexpath, "w") as _:
        pass
    return indexpath


@pytest.fixture
def certgrinderd_broken_yaml_configfile(tmp_path_factory):
    """Write a certgrinderd.yml file with invalid yml."""
    confpath = tmp_path_factory.mktemp("conf") / "certgrinderd.yml"
    # write file to disk
    with open(confpath, "w") as f:
        f.write("foo:\nbar")
    # return path to the config
    return confpath


@pytest.fixture
def certgrinder_broken_yaml_configfile(tmp_path_factory):
    """Write a certgrinder.yml file with invalid yml."""
    confpath = tmp_path_factory.mktemp("conf") / "certgrinder.yml"
    # write file to disk
    with open(confpath, "w") as f:
        f.write("foo:\nbar")
    # return path to the config
    return confpath


@pytest.fixture(params=["dns", "http", ""])
def certgrinderd_configfile(request, tmp_path_factory):
    """Write a certgrinderd.yml config file."""
    confpath = tmp_path_factory.mktemp("conf") / "certgrinderd.yml"
    conf = {
        "acme-email": "certgrindertest@invalid",
        "auth-hook": "echo 'authhook faked OK!'",
        "cleanup-hook": "echo 'cleanuphook faked OK!'",
        "certbot-command": str(pathlib.Path(sys.executable).parent / "certbot"),
        "certbot-config-dir": str(tmp_path_factory.mktemp("certbot") / "configdir"),
        "certbot-work-dir": str(tmp_path_factory.mktemp("certbot") / "workdir"),
        "certbot-logs-dir": str(tmp_path_factory.mktemp("certbot") / "logsdir"),
        "skip-acme-server-cert-verify": True,
        "temp-dir": str(tmp_path_factory.mktemp("certgrinderd")),
    }
    # add auth type
    if request.param == "dns":
        conf.update({"acme-zone": "acme.example.com"})
    elif request.param == "http":
        conf.update({"web-root": str(tmp_path_factory.mktemp("certbot") / "webroot")})
    elif request.param == "":
        pass
    # write file to disk
    with open(confpath, "w") as f:
        yaml.dump(conf, f)
    # return path to the config
    return request.param, confpath


@pytest.fixture
def known_public_key():
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


@pytest.fixture()
def known_private_key():
    """Define, parse and return a known private key."""
    pem_private_key = """
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----
"""
    return primitives.serialization.load_pem_private_key(
        pem_private_key.encode("ascii"), backend=default_backend(), password=None
    )


@pytest.fixture()
def known_private_key_2():
    """Define, parse and return another known private key."""
    pem_private_key = """
-----BEGIN RSA PRIVATE KEY-----
MIIJKAIBAAKCAgEArFC5JX2BV2W+PqQj728s5kJ/fbX+mVf9nTQvhwn7BZnG7zU0
Qh4E4AkYxtCf0leNSEwmUby7SDj/fAredxSwmukku39dyj8yHDBowZfc9nRcOIW6
KjmJau0jpSMFZNKS9tjboDbNVpqAIOQrtwcgPtXmRDyx7feZgMtn8IMfizza+Vrr
wDYHSaKuMPh6pDKbPsgEImeMYRdQPSJOk7WmmetRXRjEsvucrWh1x0FZpajjPAgM
HRf7w4m97x5MQmIUFXicMJfiKTsYHzcmPr14Dcrpy/Lu1lHW2ZcUjLSNmhFJAEty
dkED25Wp6cW2MffgTcNITSk84fHMMkRzSFJiQZbCF4Myo95D6OhUR9pt7XZEJiJQ
hCSrZKrdjvS+bOs3nAf2rY39ZWM7llpH2BMaT6IktK4NIRQl/vkDVI6a2MMVztDx
q4Zc6VZFrYVEe8ij+b6hFMvsOD7VJUJhCiewKQcPKZT5UJeabILLlkKgvHdAcDyu
0UXF1HnlgGVvt6n3hu+dBqOD0tQQaOaZ0958i8elb1ru0dN8I+2TvSbBz61LHWBn
fZo1j1Sv8L0Gl2SoD+C8jka/zLwXOfuxNQP8RQ77lKItT5UfImvPAEYIrALJ2vbg
bomb11aD3wQ0M88fb2jVpc9jseGo6yuL5NtrJ5BOCEGEWK3Cgg36NtLNorMCAwEA
AQKCAgBMa4yBFPUs1oGV9GO/h3XJNMqn7PPZ/A0NEBzX7dQ2+qkgY18mx3twBHjJ
i7KlrZCJ9MO10lbYw/aCg6t/8lwUh7tzsBvfW0GVAN8kpH4pixdvNdeHbHcGRd9e
GHcG7OCiuzBEEKnmc6TJcYf1pyJk26ZAsw5SNFIOracOIoj1zmpq1ijh2NRIku5f
54M0mQECyeAThgra8GT0h+eDWLdnYdZ2zEpH+pDU0xQQ52mjr4//iq4cpQtSAB+N
EcnOUwMHNrNGVcXGdV/QUDwU7SB2NXyUp8vGnwsC+x7w/A4kuu++QrejvFfCpdBy
Te3soTsIIchJ+DT5G6xsyrC57VeHdrh7HWwQ4KEmNTAPXiyL1S08aghucwsw6kAB
0UsXPnex2ww2+OJDMjaHn9FNxEsLDVSqsQJcj2/xVtrV38CsoaFv2jJa5SSCBehN
vCMmA48rUz+zKGvkT1KHyFwEZoEgBEfws2U/egMHILkqqai8m09IwIsIIkFO8dBo
VsvsoIv05dDV9CqUEqDhKeObeyg79xJ8rm+86c3+Bmkr6J+lqP7W4+CFVkFOJTqC
MkRhUSB8Mj+4f7HTFFpAg2ZSsNP7uazBJd+7NRikzlXU0XAbj78ycWP6SbXzOGhM
k1kla1E8/wLwOtunFkEKfBtRYNU57Y/3hgtjkYRWmd6omAp8KQKCAQEA2QxjlQ5U
sTRS26QapyNqH9jzHY5h+ucSwwkzgZjpU2uJl5wivy+a6SsSu5Senlec5XgMyuqS
729B5/H26/r1K2WH4f7W2zqsQrowiJRyKefeiYhyo8wuciO6apfcZ/CWfpZzr4oO
IvxHSVfllZMtw0ZR/0JKO6HgPPCDB0GZT/MVxGMWi2XNj/vmItkfptem8eceiJpW
yb6v1cCKhGIgVEUwdyZRqcQ7ojahZVQuauq2obF190mSVDzcTituRnl/IN9jzBD6
J568W8sfU9i7I/4iRRhxZtFCsUZoYiSCog2snU7N+I5N0Ulvx45zFhz49ZXkVPh3
LtIt37x+1QKCDQKCAQEAyz02hmbFSHh9LprWzVmOiOea2hXvk1UBu5IfI8wnWi/T
quqaZ9jPD79XrK3EaYX90hI4B80zxJSgssmBRECjOx4Wyv48cCljm2Tpu89iJDdP
uZMlnx5igGIekWUz9neCxbQ77lk9uTMzB0wl+Ln3+Vb6ixNnXTQNk8OVza9leIgJ
QYM0G73NM8J1cL/oczAKBNpD4jBx1D32IOd2OjvVo3ryjPiemgp3JN+J8XEKuiYU
cRTY87CnDsR9CWzQaPMYQFF9FJFzbcRg5H1vNT32hrXt3vz4iDqrfWgMq0JW2Pde
rtBQ56GTJsmuM6U/SGejigeED8CL3efhjbK+lRFHvwKCAQAt1f/xqmUYRwR4fd9j
DIeM0jQFOdxXMBU2Ous1oyUjCMK10bNEzLjaJM5/7pLQvY/UpdWNxJvjFIvGf8K1
cvnzgC2B/F9DTNC0Br3ZGgBB+UV1pesPzD7Cu+jSOd/B03z0nrEvkOgLW1tyka1a
OQqhAmiuj0E99qF0PRZuodvOlncyUfqg1Y7jqT6gfVnB0ijfTP+VuYI6eJqJeW/H
JTHOmg3yG5WDVH2DdCYBUBW9XnPTEbbn0hGk2HVtzJ4tI9tFBef9YFhzpYIBoJOt
EUf0Aeca0F6iZ+69oTDKCQvNTTX2wn2cz/B/EhMZAWwsb1HkCxN9HjuNF7W4WgYu
1ajBAoIBADGzr5DgsyBM7vglv6AKZbQPR6xLrwINyNWxH1Jmy7zfc1kZ9FavC7wj
I/LDsAPKU886y18FDMLnQgFXC/jAAeskKZjM4cTgKk7HN+3JAowuxp1wYcPu71HM
LQOLh1Cf22gz8nAQfOq8nZ8MPUD9YaolXjICtcVyRFu9efYKDbuTMQhHaMfb+8HL
rWK8W8FHnzuekPlQtZWc7YMQd7Y4Cb/oAkb9SfQL2SU4UYitB12MkHUzDvdRXRlc
beOPK8xunqCkDP2psFvIqZVXI4oWtCIvfZOJs9HE30lU17xOBeUbYZlIsnBi8BSN
P7+7iqVPSwwnWGFtygajfWJksvzLdAsCggEBALagd+ddMEz/qCl7kht7x/9xrNLf
B6W09K2BrBhC3LsFiqXTnAK8wrwFaO2VMmdFf8HTlYwGmp4zicUvH5haWsdQW1/O
McdHz3R43bFptIPffKnIPT/pmbCTfQBbowSAsTZXmc6sJC1gSt0dpT8sRzQh8ktw
srMtXLgwdlmRlAVigTU2rl/CSH/7dg057y44GpYEjiaUQl2COEmj8zEPfAbZf4yG
cZktnz+4CRiZJe1PKZT+od8K0p1+Nww4laYBIbD4Fu8NTEfXy0txGZSXmBdmyfpt
YX3s0pnrpLb4bUg24R3zmvDyCXXghd9zv+Dhaf3Uf2DNEGwDBxNPISOj2ck=
-----END RSA PRIVATE KEY-----"""
    return primitives.serialization.load_pem_private_key(
        pem_private_key.encode("ascii"), backend=default_backend(), password=None
    )


@pytest.fixture()
def known_private_key_3():
    """Define, parse and return yet another known private key."""
    pem_private_key = """
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----"""
    return primitives.serialization.load_pem_private_key(
        pem_private_key.encode("ascii"), backend=default_backend(), password=None
    )


@pytest.fixture()
def known_private_key_4():
    """Define, parse and return one more known private key."""
    pem_private_key = """
-----BEGIN RSA PRIVATE KEY-----
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
-----END RSA PRIVATE KEY-----"""
    return primitives.serialization.load_pem_private_key(
        pem_private_key.encode("ascii"), backend=default_backend(), password=None
    )


@pytest.fixture
def known_csr():
    """A PEM formatted CSR for example.com,www.example.com."""
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


@pytest.fixture
def csr_with_two_cn():
    """An invalid PEM formatted CSR for example.com,www.example.com with two CommonName attributes."""
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
def csr_with_cn_not_in_san_list():
    """An invalid PEM formatted CSR where the CN example.com is not in the SAN list."""
    csr = """
-----BEGIN CERTIFICATE REQUEST-----
MIIEiDCCAnACAQAwFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wggIiMA0GCSqGSIb3
DQEBAQUAA4ICDwAwggIKAoICAQDT6T4eChNkmhsPWpANXfZYffT43n8qV7RFuSd8
ng4O1Xc0isLdpmFCt6kZ4BVxZtz56OGAGEIrmWUUM1oqrO9u4bZAhFPYQ/UK7cJl
MO/3yIDBNGHRVzaHPZllkx82d+NrK8qOTWVuz47PWWTH64p5AxAjf1Su8K3Mk9L8
n6o5s4RBqa9veL56/eQ5l2ytOqtanz0ZTRP4lg0xHMaItXK2ooIoAnka5NDb7seI
uQZt43QBIpE6NAPK7BRrHmwGp2mJCon1XOd/wy8PLqDMFthSLs3SSMEUL/tZCxzp
dMNQDF0E5ogl82hPJVbx/Hz4GxBRroFMciZIO/2neOV8akFEPfVWaaistzRFkkxf
zVOw4wRPAeEI6iOIoqwuCf6Ozh12eeP0oLjJBs8HGfOkw2sLuUeZ6/dKDZ0zIfy4
82C2xNh47HSicLCM/zX7hodUJkYtwCMzQaauozlY+2hvc+Je7F5feKEv1SCRsIgp
pZb8W5Yk4526n037zamqpi4SUhibtGTGmua3qH6S5gr8lbQg59vBv4dLs1KgXx64
iyCbQvSXaTUyVVvcEyptNedsaJJ6ogExfNKztO4wZL8Juw+ZiHsd1cd7kFNBfU62
MN9RXEL70RftRXKdIj9f0GFXrH8tqeWr0WiOKyJ9chqffUJM15n2Hrd3o2pD0iBt
dHyMpwIDAQABoC0wKwYJKoZIhvcNAQkOMR4wHDAaBgNVHREEEzARgg93d3cuZXhh
bXBsZS5jb20wDQYJKoZIhvcNAQELBQADggIBAHSe4EKe6RChIm4aOe8GlkOIMkAT
H6NJLKpKhVKk7NsaG4VP8vXS6kPOeDHgmVXGqAdNORhIfkrdNUMYheHf/XlozVzv
R9KOCSL7wd+Pg8JWH3a7SmeKHzZE1EKjJYnWcpSU+xi+/EyupDtbCglKX79B37Wh
Fico0perPVQafI9Kcr/SPLNS/R/FyvCUkmReY+wYv7b3EYP6z/Ru4ByDuU9INj0a
OQTOLTeIOs2Oa6dAWeJse1nwbQT72gtN+tBB2jT6XHj4s+8D2AmARVv7G64noYAF
J4XOp4n/Q/xVaelAz8fVGClilyAIJigJ6ouJ6v5w1drxY3sw3kgcZX6pCVkm4Dn8
N1ttJC+JWIOinAKI44f6dwBwB/hLyn8flCqGy85zJBrW3KK5jBChhcrCkhbkasQJ
PqIK1UAbPiVvhk8RrRoRj2RGRBrSr2GmznXYTVQuOWwU5K14aRaEoawxmcY/0JD4
13pmoznCtXvX5/acZtN4Yv+FQbYoabFUa5liNyrszJQ86nh+dRjO24R4tBeL363n
mHhfttwvNq8iXVPlQTE6Jmaph2mh+SUiokrKaw54f487Agg0kM2emEFImZcEx1Qs
yb9zp23eleOTPnni3asK2t0E08yIgPILjuzJ875OiSgSTjASesmjGf7lSZP53hjP
pKA7KJjOAUWagWnA
-----END CERTIFICATE REQUEST-----"""
    return csr


@pytest.fixture
def csr_example_org():
    """A PEM formatted CSR for example.org,www.example.org."""
    csr = """
-----BEGIN CERTIFICATE REQUEST-----
MIIElTCCAn0CAQAwFjEUMBIGA1UEAwwLZXhhbXBsZS5vcmcwggIiMA0GCSqGSIb3
DQEBAQUAA4ICDwAwggIKAoICAQCUil7U19gr1V6XxE5LkthupD4pGD+eukdq1JkZ
b167h2NJuQUqjw2FQsDwPy6doI50RvcjJrfNR13Hw37wex+YoG3KJ0Z0apkY53LG
Ok5QsFS/kmObUtTyH7ybnjpPhzw+CD5CdPFfyBOvUofcbhKKcIqHPneI+qJ2+6rH
559UO70ux4EDOc0AneeGHj5fciGvqTQYKv2KUCs/dnaQTYgYw/sUDuQujHGAiNVI
LjBaVRJt6BIcv43RDNmm2vjRAjZTizXN0aFDgH8o5wAw3vopMEldNV2yN9kDZNRU
A9kGNN1fUTGpP8YvK8ktBGqCT13zBURTcWzK9vgqfeSzT6eYY9tzElIBsdkfk4+c
O+fg4Q/pyv45AKIQicrhJ8LyQxGS1uw5IGte7HhVMY5cYerEPzBGdLNO6foV29Lp
NoaAuAhQKyxVCguO0UyCcDXuSVSzHy+6dw9Re60mFs62bu6yaAndWYNDR3KIyfe7
zz36gWlsye+2UgDrfmj+lATHfdpujP2x5U6GkhbxuT86xJBvMzBEcJwVvqjVjvLq
d/6CrhmalJx+yzDMtivVPglmdi6ng45/2Q/jdBfvhd0wR/aPsL+24dgcZeFJ0xSB
dJ3fdWsL2vuxxF/awdmuuMaybzwLzy0RDHpDReRhHFIDLoR9KGdF/wk64XiHQYFA
vXl91QIDAQABoDowOAYJKoZIhvcNAQkOMSswKTAnBgNVHREEIDAeggtleGFtcGxl
Lm9yZ4IPd3d3LmV4YW1wbGUub3JnMA0GCSqGSIb3DQEBCwUAA4ICAQBCmWvyLECn
EZdrZHsBmIDhAZzdNSBTTu0WDmG6Ic6ErKIP0N+YCf6y0HveHossTGNlYRz/phKk
H4c+X0MEXoiUTd0NrLry0yeorHLMj2JWAn1N/oiBtgQma8sNaxJjGXzsA5jFBqmR
xwiMq9CMLm+J8ZrKL9bjU9SP+JJpGHCX8CWZJFHfC0hOr0rMZlsrLWFakb0ou01/
aScveQ/EjtQul1KFl3zepFKsDDhPc2rSQPdXRDckvMqHizBTdOJ87azUzTT0R/Id
tlD5XsPnGocgrQX+ysBMPX0I8z0FO3EHwYc118rF2B37FbPIAzAys/wL++iCsmzg
ktCDNt+UjmZ1kFcsewtM+DI4euKgI69HI3V4ET42GF7ISarObAtDKF3GWebr9093
emqK4qtaSHo0Wb0Ahr0UAWTea2EDbEh7YsjIdVq6K9tg7ZXlY0DPbqAH5FLM43Qm
/PxI1wsJSYOz2c0u9pvXL51MzQf10t9qCUhO/KWO3yzciiEbkJdUKVF1N9st2nef
oF60TAp7H4S0q77YSnO14CoXgx3o5Y2idM6Aciexu89AcIZYwpWRrtgJgIrLRqxK
Q5SGFmRh72w2H7c1OPiePk/HVLIZLqbG53pJ1m+IAh3w27ee3WEEZIX6uwZhwM8j
KTDvlTiQSl+cy49SkgWsFlUukwkJJPzU7g==
-----END CERTIFICATE REQUEST-----"""
    return csr


@pytest.fixture
def csr_example_com_and_org():
    """A CSR for example.com,www.example.com,foo.example.org."""
    csr = """
-----BEGIN CERTIFICATE REQUEST-----
MIIEpjCCAo4CAQAwFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wggIiMA0GCSqGSIb3
DQEBAQUAA4ICDwAwggIKAoICAQCUil7U19gr1V6XxE5LkthupD4pGD+eukdq1JkZ
b167h2NJuQUqjw2FQsDwPy6doI50RvcjJrfNR13Hw37wex+YoG3KJ0Z0apkY53LG
Ok5QsFS/kmObUtTyH7ybnjpPhzw+CD5CdPFfyBOvUofcbhKKcIqHPneI+qJ2+6rH
559UO70ux4EDOc0AneeGHj5fciGvqTQYKv2KUCs/dnaQTYgYw/sUDuQujHGAiNVI
LjBaVRJt6BIcv43RDNmm2vjRAjZTizXN0aFDgH8o5wAw3vopMEldNV2yN9kDZNRU
A9kGNN1fUTGpP8YvK8ktBGqCT13zBURTcWzK9vgqfeSzT6eYY9tzElIBsdkfk4+c
O+fg4Q/pyv45AKIQicrhJ8LyQxGS1uw5IGte7HhVMY5cYerEPzBGdLNO6foV29Lp
NoaAuAhQKyxVCguO0UyCcDXuSVSzHy+6dw9Re60mFs62bu6yaAndWYNDR3KIyfe7
zz36gWlsye+2UgDrfmj+lATHfdpujP2x5U6GkhbxuT86xJBvMzBEcJwVvqjVjvLq
d/6CrhmalJx+yzDMtivVPglmdi6ng45/2Q/jdBfvhd0wR/aPsL+24dgcZeFJ0xSB
dJ3fdWsL2vuxxF/awdmuuMaybzwLzy0RDHpDReRhHFIDLoR9KGdF/wk64XiHQYFA
vXl91QIDAQABoEswSQYJKoZIhvcNAQkOMTwwOjA4BgNVHREEMTAvggtleGFtcGxl
LmNvbYIPd3d3LmV4YW1wbGUuY29tgg9mb28uZXhhbXBsZS5vcmcwDQYJKoZIhvcN
AQELBQADggIBAF6DCYBsGvKmpLez0+wKTOCNJG84ByL0Jmjyr2NoUkGRSWGbQW6q
JJUuXTm7vZZrGy70aND5gW5ofjq1/mn6cLyfjcZSa7U+XkWCxTmFhP1S/OIoTrWF
CM2lm4fA85XNm1DuxZfaKvdXi+pjjfknLrtUtCExx/JLTRnrkSDWsnF14A1zYuSI
ZqRr/VRW8o8Nx88Yxi/gws36SjbQu4lvAhy7p120mZhk4IWVXsu9B+dxE6PdD+AK
jt//m3yjjPXfzZ0m2EuYOJA22N64iDg2E8gH1X3Vln/3hgOO7TVoOF2UhdXKKvYm
+chI6LDvYE8KJO6/oTvGu0qJVzCrP6+acIFQ3SNdwF6Kwg7r7yKXsKnfrh6/JVtF
7jbm3trFycXQL47qYDFYKjOlmTPx/awGfDZqhkrv0Za2aRpCgjKLSK4CJ00cdVpx
ORf1UHb8t6MDv5qOdL9eIa+TDECWUGK2LGCc75MQAvQVU3E8XLuts33oMNExxeG9
3P4ng3DhwzpegzI+QwH5OpBrlLPr4PkzW7UF8vf3GaPORbYi//rLC40QN4jvTHTp
L4COL0UajaWs1L9UXyxD/wSS/HcSVw1NS9+cmQYTpgPnz2dbOj6twklrq9NzEUt7
vMjDUV30GSeQe5KxMR3TmXUFXVXyJEr5FbcWIO//e3pYSBfEra1QDh6w
-----END CERTIFICATE REQUEST-----"""
    return csr


@pytest.fixture
def certgrinderd_env(monkeypatch):
    """Whip up a fake CERTGRINDERD_DOMAINSETS environment for certgrinderd."""
    monkeypatch.setenv(
        "CERTGRINDERD_DOMAINSETS", "example.com,www.example.com;example.net"
    )


@pytest.fixture
def no_certgrinderd_env(monkeypatch):
    """Delete CERTGRINDERD_DOMAINSETS environment variable."""
    try:
        monkeypatch.delenv("CERTGRINDERD_DOMAINSETS")
    except KeyError:
        pass


@pytest.fixture
def selfsigned_certificate(known_private_key_2):
    """Return a selfsigned certificate, only valid for 10 days."""
    subject = issuer = x509.Name(
        [
            x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, "DK"),
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "example.com"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(known_private_key_2.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=10))
        .add_extension(
            x509.SubjectAlternativeName(
                [x509.DNSName("example.com"), x509.DNSName("www.example.com")]
            ),
            critical=False,
        )
        .sign(known_private_key_2, primitives.hashes.SHA256(), default_backend())
    )
    return cert


@pytest.fixture
def signed_certificate(known_private_key, known_private_key_2):
    """Return a signed certificate."""
    subject = x509.Name(
        [
            x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, "DK"),
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "example.com"),
        ]
    )
    issuer = x509.Name(
        [
            x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, "DK"),
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "example.net"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(known_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=90))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("example.com")]), critical=False
        )
        .sign(known_private_key_2, primitives.hashes.SHA256(), default_backend())
    )
    return cert


@pytest.fixture
def delegated_signer_certificate_not_signed_by_issuer(
    known_private_key_3, known_private_key_4
):
    """Return a signed certificate with the ocsp signing permission, but not signed by the issuer."""
    subject = x509.Name(
        [
            x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, "DK"),
            x509.NameAttribute(
                x509.oid.NameOID.COMMON_NAME, "delegatedresponder.example"
            ),
        ]
    )
    issuer = x509.Name(
        [
            x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, "DK"),
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "delegatedissuer.example"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(known_private_key_3.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=90))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("delegatedresponder.example")]),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(usages=[x509.oid.ExtendedKeyUsageOID.OCSP_SIGNING]),
            critical=True,
        )
        .sign(known_private_key_4, primitives.hashes.SHA256(), default_backend())
    )
    return cert


@pytest.fixture
def delegated_signer_certificate(known_private_key_3, known_private_key_2):
    """Return a signed certificate with the ocsp signing permission."""
    subject = x509.Name(
        [
            x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, "DK"),
            x509.NameAttribute(
                x509.oid.NameOID.COMMON_NAME, "delegatedresponder.example"
            ),
        ]
    )
    issuer = x509.Name(
        [
            x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, "DK"),
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "example.com"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(known_private_key_3.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=90))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("delegatedresponder.example")]),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(usages=[x509.oid.ExtendedKeyUsageOID.OCSP_SIGNING]),
            critical=True,
        )
        .sign(known_private_key_2, primitives.hashes.SHA256(), default_backend())
    )
    return cert


@pytest.fixture
def delegated_signer_certificate_no_eku(known_private_key_3, known_private_key_2):
    """Return a delegated signer certificate without ExtendedKeyUsage extension."""
    subject = x509.Name(
        [
            x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, "DK"),
            x509.NameAttribute(
                x509.oid.NameOID.COMMON_NAME, "delegatedresponder.example"
            ),
        ]
    )
    issuer = x509.Name(
        [
            x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, "DK"),
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "example.com"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(known_private_key_3.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=90))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("delegatedresponder.example")]),
            critical=True,
        )
        .sign(known_private_key_2, primitives.hashes.SHA256(), default_backend())
    )
    return cert


@pytest.fixture
def delegated_signer_certificate_no_ocsp_perm(known_private_key_3, known_private_key_2):
    """Return a signed certificate with eku but no ocsp signing permission."""
    subject = x509.Name(
        [
            x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, "DK"),
            x509.NameAttribute(
                x509.oid.NameOID.COMMON_NAME, "delegatedresponder.example"
            ),
        ]
    )
    issuer = x509.Name(
        [
            x509.NameAttribute(x509.oid.NameOID.COUNTRY_NAME, "DK"),
            x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "example.com"),
        ]
    )
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(known_private_key_3.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.utcnow())
        .not_valid_after(datetime.datetime.utcnow() + datetime.timedelta(days=90))
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName("delegatedresponder.example")]),
            critical=True,
        )
        .add_extension(
            x509.ExtendedKeyUsage(usages=[x509.oid.ExtendedKeyUsageOID.CODE_SIGNING]),
            critical=True,
        )
        .sign(known_private_key_2, primitives.hashes.SHA256(), default_backend())
    )
    return cert


@pytest.fixture
def certificate_chain_file(tmp_path_factory):
    """Return a PEM formatted certificate chain."""
    certpath = tmp_path_factory.mktemp("certificates") / "example.com.crt"
    chain = """-----BEGIN CERTIFICATE-----
MIIEnTCCA4WgAwIBAgIIJfMqOpI92mgwDQYJKoZIhvcNAQELBQAwKDEmMCQGA1UE
AxMdUGViYmxlIEludGVybWVkaWF0ZSBDQSAwN2E2OWQwHhcNMjAwODI3MjEwOTI1
WhcNMjUwODI3MjEwOTI1WjAWMRQwEgYDVQQDEwtleGFtcGxlLmNvbTCCAiIwDQYJ
KoZIhvcNAQEBBQADggIPADCCAgoCggIBAL/ktXP5JKtwgsNRpxmTM4326x5w6Vc2
7lMWxmQKHj9GWHly+IiRegX4Z/EvGfMKsejfDduO19TWT7ox5+s5yIHiuKOu2l7e
wdDG9VATvUSunThOsNZfERAbb02LHKW+/LLzUwWfzJMaX1fr9OC4yFsktZAJAzgf
etQDUNS4CsZzeijTp/Dus58/OoQDHmoZ4IXH8SujOs0BcNkSYvL3bDvOCmorriKs
byNrzYL1gxixX8FQUjYUgdrXTHJZyETmf3v27z3JMpQ68ymB6P+Mnd8OC3DC4WN5
V68BUavt7ONehL2rjrvZf36i3IcfWPLzwSLgB514Hp++bEHPSlXIthzYoyCYJ0BV
gxrKKM4mlrHs2vZY/CYN9EwgZt7krPYA/7jVbVRyhdbsaaVnHOkb7jdqVU8jysF+
yR+x53T1qmQsDWpOS6aSy1eku0qcDSwlzMjRBpjlpgPKJfnT5og+tkU6HiMJI4XJ
vt/QX2/1/ZKwCpg+iWekynZv3QvTmaOJVNfW/IhaKD8dqr8ZTd5+rSv1QI1fX/0z
hTsZ2rruyq3kZ6gRQfia79qEfERE/bboxk5YwZQVHFUBELF/BOoCM4W8UpBFS1jI
LV9rD0sxE9/R9BXPQ48wiWRhXt4b9ot7SbSkuBKXvk6DclFiA9e4ti7eMrEiDECD
rwqGrBuR0Yn9AgMBAAGjgdwwgdkwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQG
CCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBT44sOi
jKhrhmB2DnPjLW8gJ6uKwDAfBgNVHSMEGDAWgBTGg0QCjUOiYfRi7xIqJErMHQLt
fzAxBggrBgEFBQcBAQQlMCMwIQYIKwYBBQUHMAGGFWh0dHA6Ly8xMjcuMC4wLjE6
ODg4ODAnBgNVHREEIDAeggtleGFtcGxlLmNvbYIPd3d3LmV4YW1wbGUuY29tMA0G
CSqGSIb3DQEBCwUAA4IBAQA/EIgQhYRiUTsAxFXRO/GfDaA0Xly012eSx3pLeoFy
SYGD7nEKCCfSbfJ9ZfBkDVEeEfQX5hpQRmsbSx3YHzkAaT0UXKE2djPzylHRhUjZ
AvCbRX8Vbtu0zE2d9isJzRC5VrTKoHixairJuhkqiGl6DEvTrdzmUORlj+WYHqL2
1riv3PC5AelR2fP8fWvwEvEdEE7y8a9o/dcYDilELoG6UAuah1SJOY3yfitST44e
HlgnIoGrPZwTpa1cViUfSCEpBzKHHu4lS97ZVtli6uiOfFftVi5rc2+BLTkQOKbk
fuhmbiA5k35QDGQ69N2ZGveE2VJ6nOU1zOOyCGGwzxSh
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDUDCCAjigAwIBAgIIGNqbINwL+g0wDQYJKoZIhvcNAQELBQAwIDEeMBwGA1UE
AxMVUGViYmxlIFJvb3QgQ0EgMmZjMjZkMCAXDTIwMDgyNzIxMDg1NVoYDzIwNTAw
ODI3MjIwODU1WjAoMSYwJAYDVQQDEx1QZWJibGUgSW50ZXJtZWRpYXRlIENBIDA3
YTY5ZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKPKzG5/lRLbBWhp
qRcG/0Bfdfs6D6RZGQnPHVOymFkoDXMv4Nva9EGPo875Hdc6stz3a/bvGVZJd0Ud
F94QmCUspDFy0f6+VRI1UGoPpHwpRPaBmAXuuHrY8qiF/ZoNmsTPUmdlhzWGXegK
WAVTtDUaVJobXC2LEL1cWiUlb7pzIdLMODDqXM5v6dkcp/r6nvHVyV1jk56cyXVo
dvxKK7lW1E5fYgNlwU7Lp94qdnphaSIeZYcvoiBVvKxCAPW63F4SaKabxv9U+iql
Tbvep2/+2lWSrg0e6FNU7JMBw5af6ziZl0YElbRh0Es7VnTItP4W0m/VKBPEXnxn
uboViA0CAwEAAaOBgzCBgDAOBgNVHQ8BAf8EBAMCAoQwHQYDVR0lBBYwFAYIKwYB
BQUHAwEGCCsGAQUFBwMCMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFMaDRAKN
Q6Jh9GLvEiokSswdAu1/MB8GA1UdIwQYMBaAFJjeDmkMtjjHIRrMownx6qFHf0Qs
MA0GCSqGSIb3DQEBCwUAA4IBAQBtKwt/c/DwgGTJVwvafH/K2WMJVmos/TztNsT8
uwOGcbZV2GIM1EtBuT/0Iqdp/ICH9sRuYSfljEsUPEHtBBK6EsnK/VZb6bED0EM2
IqRXUUdx6t1mWJDLnfGllIDWmxEyUmqwMcMLEkYVg4RdZL16AmPRU1gEXmr5qY5B
8V9OQteW42Q9O3DcFkqOKuNoYZKt+FUqRKyK+azFoElDGBEtf7Nci6Tu1fICGnYs
4ps029spwvtZAh+xFaza1ScWrllQf/mA5a7/Hd3xm3WC6ho5rUtdC1NpSWh0rJGc
M6lczEk5TdIIKWGEOnqAxLwxXYa6xe+z6mr1bJMQZHuJS9sQ
-----END CERTIFICATE-----"""
    with open(certpath, "wb") as f:
        f.write(chain.encode("ASCII"))
    return certpath


@pytest.fixture
def certificate_chain_file_broken_cert(tmp_path_factory):
    """Return a PEM formatted certificate chain where the cert is invalid."""
    certpath = tmp_path_factory.mktemp("certificates") / "example.com-certbroken.crt"
    chain = """-----BEGIN CERTIFICATE-----
foo
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDUDCCAjigAwIBAgIIGNqbINwL+g0wDQYJKoZIhvcNAQELBQAwIDEeMBwGA1UE
AxMVUGViYmxlIFJvb3QgQ0EgMmZjMjZkMCAXDTIwMDgyNzIxMDg1NVoYDzIwNTAw
ODI3MjIwODU1WjAoMSYwJAYDVQQDEx1QZWJibGUgSW50ZXJtZWRpYXRlIENBIDA3
YTY5ZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKPKzG5/lRLbBWhp
qRcG/0Bfdfs6D6RZGQnPHVOymFkoDXMv4Nva9EGPo875Hdc6stz3a/bvGVZJd0Ud
F94QmCUspDFy0f6+VRI1UGoPpHwpRPaBmAXuuHrY8qiF/ZoNmsTPUmdlhzWGXegK
WAVTtDUaVJobXC2LEL1cWiUlb7pzIdLMODDqXM5v6dkcp/r6nvHVyV1jk56cyXVo
dvxKK7lW1E5fYgNlwU7Lp94qdnphaSIeZYcvoiBVvKxCAPW63F4SaKabxv9U+iql
Tbvep2/+2lWSrg0e6FNU7JMBw5af6ziZl0YElbRh0Es7VnTItP4W0m/VKBPEXnxn
uboViA0CAwEAAaOBgzCBgDAOBgNVHQ8BAf8EBAMCAoQwHQYDVR0lBBYwFAYIKwYB
BQUHAwEGCCsGAQUFBwMCMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFMaDRAKN
Q6Jh9GLvEiokSswdAu1/MB8GA1UdIwQYMBaAFJjeDmkMtjjHIRrMownx6qFHf0Qs
MA0GCSqGSIb3DQEBCwUAA4IBAQBtKwt/c/DwgGTJVwvafH/K2WMJVmos/TztNsT8
uwOGcbZV2GIM1EtBuT/0Iqdp/ICH9sRuYSfljEsUPEHtBBK6EsnK/VZb6bED0EM2
IqRXUUdx6t1mWJDLnfGllIDWmxEyUmqwMcMLEkYVg4RdZL16AmPRU1gEXmr5qY5B
8V9OQteW42Q9O3DcFkqOKuNoYZKt+FUqRKyK+azFoElDGBEtf7Nci6Tu1fICGnYs
4ps029spwvtZAh+xFaza1ScWrllQf/mA5a7/Hd3xm3WC6ho5rUtdC1NpSWh0rJGc
M6lczEk5TdIIKWGEOnqAxLwxXYa6xe+z6mr1bJMQZHuJS9sQ
-----END CERTIFICATE-----"""
    with open(certpath, "wb") as f:
        f.write(chain.encode("ASCII"))
    return certpath


@pytest.fixture
def certificate_chain_file_broken_issuer(tmp_path_factory):
    """Return a PEM formatted certificate chain where the issuer is invalid."""
    certpath = tmp_path_factory.mktemp("certificates") / "example.com-issuerbroken.crt"
    chain = """-----BEGIN CERTIFICATE-----
MIIEnTCCA4WgAwIBAgIIJfMqOpI92mgwDQYJKoZIhvcNAQELBQAwKDEmMCQGA1UE
AxMdUGViYmxlIEludGVybWVkaWF0ZSBDQSAwN2E2OWQwHhcNMjAwODI3MjEwOTI1
WhcNMjUwODI3MjEwOTI1WjAWMRQwEgYDVQQDEwtleGFtcGxlLmNvbTCCAiIwDQYJ
KoZIhvcNAQEBBQADggIPADCCAgoCggIBAL/ktXP5JKtwgsNRpxmTM4326x5w6Vc2
7lMWxmQKHj9GWHly+IiRegX4Z/EvGfMKsejfDduO19TWT7ox5+s5yIHiuKOu2l7e
wdDG9VATvUSunThOsNZfERAbb02LHKW+/LLzUwWfzJMaX1fr9OC4yFsktZAJAzgf
etQDUNS4CsZzeijTp/Dus58/OoQDHmoZ4IXH8SujOs0BcNkSYvL3bDvOCmorriKs
byNrzYL1gxixX8FQUjYUgdrXTHJZyETmf3v27z3JMpQ68ymB6P+Mnd8OC3DC4WN5
V68BUavt7ONehL2rjrvZf36i3IcfWPLzwSLgB514Hp++bEHPSlXIthzYoyCYJ0BV
gxrKKM4mlrHs2vZY/CYN9EwgZt7krPYA/7jVbVRyhdbsaaVnHOkb7jdqVU8jysF+
yR+x53T1qmQsDWpOS6aSy1eku0qcDSwlzMjRBpjlpgPKJfnT5og+tkU6HiMJI4XJ
vt/QX2/1/ZKwCpg+iWekynZv3QvTmaOJVNfW/IhaKD8dqr8ZTd5+rSv1QI1fX/0z
hTsZ2rruyq3kZ6gRQfia79qEfERE/bboxk5YwZQVHFUBELF/BOoCM4W8UpBFS1jI
LV9rD0sxE9/R9BXPQ48wiWRhXt4b9ot7SbSkuBKXvk6DclFiA9e4ti7eMrEiDECD
rwqGrBuR0Yn9AgMBAAGjgdwwgdkwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQG
CCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBT44sOi
jKhrhmB2DnPjLW8gJ6uKwDAfBgNVHSMEGDAWgBTGg0QCjUOiYfRi7xIqJErMHQLt
fzAxBggrBgEFBQcBAQQlMCMwIQYIKwYBBQUHMAGGFWh0dHA6Ly8xMjcuMC4wLjE6
ODg4ODAnBgNVHREEIDAeggtleGFtcGxlLmNvbYIPd3d3LmV4YW1wbGUuY29tMA0G
CSqGSIb3DQEBCwUAA4IBAQA/EIgQhYRiUTsAxFXRO/GfDaA0Xly012eSx3pLeoFy
SYGD7nEKCCfSbfJ9ZfBkDVEeEfQX5hpQRmsbSx3YHzkAaT0UXKE2djPzylHRhUjZ
AvCbRX8Vbtu0zE2d9isJzRC5VrTKoHixairJuhkqiGl6DEvTrdzmUORlj+WYHqL2
1riv3PC5AelR2fP8fWvwEvEdEE7y8a9o/dcYDilELoG6UAuah1SJOY3yfitST44e
HlgnIoGrPZwTpa1cViUfSCEpBzKHHu4lS97ZVtli6uiOfFftVi5rc2+BLTkQOKbk
fuhmbiA5k35QDGQ69N2ZGveE2VJ6nOU1zOOyCGGwzxSh
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
foo
-----END CERTIFICATE-----"""
    with open(certpath, "wb") as f:
        f.write(chain.encode("ASCII"))
    return certpath


@pytest.fixture
def certificate_chain_file_not_a_pem(tmp_path_factory):
    """Return something which is not a PEM formatted certificate chain."""
    certpath = tmp_path_factory.mktemp("certificates") / "example.com-not-a-pem.crt"
    chain = "foo"
    with open(certpath, "wb") as f:
        f.write(chain.encode("ASCII"))
    return certpath


@pytest.fixture
def certificate_file_no_aia(tmp_path_factory):
    """Return a cert with no AUTHORITY_INFORMATION_ACCESS extension."""
    certpath = tmp_path_factory.mktemp("certificates") / "example.com-no-aia.crt"
    cert = """-----BEGIN CERTIFICATE-----
MIIEWTCCA0GgAwIBAgIINaRKcLY1618wDQYJKoZIhvcNAQELBQAwKDEmMCQGA1UE
AxMdUGViYmxlIEludGVybWVkaWF0ZSBDQSAxNzY2ZmUwHhcNMjAwODI4MDUzODAw
WhcNMjUwODI4MDUzODAwWjAWMRQwEgYDVQQDEwtleGFtcGxlLm5ldDCCAiIwDQYJ
KoZIhvcNAQEBBQADggIPADCCAgoCggIBAJNRb78bno1y9h8GO+vHGNkZ5hlcUt3x
F70WPU9H09K1WCl5QoVsfDOTYl6tl9k1GaIaNM9cBxgAen9+7AGBjJ0HQQdaHjEP
Hdcrf/M7YBNdAkrZr4mUWTOjvQW8RdEyzprTRVErVuoKojuipyieAOnYBkIRqZZR
+PRAeizMsPSgGt2gOCAGbNuheScN8Ms6jFh/Lkh/2lYFzeZGq/xrQeiRIWha+1OQ
kCqRy+NckI+oI3fE2gUIuqo2uwVvC4Wxfrhi+Ktw45s997ZbU+KxUujPbDpwNGZJ
Blipis1XwqcoER9L1KTvTpcJxZL/xM9K2wCP1VZ63QOz3AsGG12lNJ5v5BPdl1LE
/myTIo4KWfLx41AUIefYw++JPlp+P7ET8NgTMUOQeTJslQ5k2AMmtE+FnCHhbyyr
QcDdRrAjKlo2CvrOxpSOnEW2slU6vLvQ8FUiXPXHccX9YUAkaRn7FPG1eGci8MHy
kUvqshSw3xshEmg+4WJIe7+xPwdaByiqD/b9kKTPwwfPjiKNrzl6NTdC9sJ/474B
/L6AvwjPWplhWBTFgIrfGfT0GUmsVq61Dp85Esr7bQRSoxwaW+uwTfY2glCBMGjt
CPp5zdqIvaLSlUwBBRnDdpsrE+jf2LTcQ4beqNfyWHp0O2MzThldRLHe5vTtrtew
Xr7I8xKkNqlRAgMBAAGjgZgwgZUwDgYDVR0PAQH/BAQDAgWgMB0GA1UdJQQWMBQG
CCsGAQUFBwMBBggrBgEFBQcDAjAMBgNVHRMBAf8EAjAAMB0GA1UdDgQWBBSdAsMM
6+jpZX6pgsMWkkM82UqjCjAfBgNVHSMEGDAWgBScLIFnUPMB9ZpvS+OUFdiFnR8x
GjAWBgNVHREEDzANggtleGFtcGxlLm5ldDANBgkqhkiG9w0BAQsFAAOCAQEAS6w6
MTUgd32WbdOZjeneFchx6hhGgMRqg/6FcqV+gQj1q/EJ156RVmuauZZEgoqCcSn5
TTdhGHPO/h/T+JkGB7A5jvonryI2NLe0lUfGY2aLBKq3ed8/qZr7jTRkj9Og5TRC
g/xFXgUYEjb3ijP95RwP6W14lYTK4W3ABB6UYEQxTix67ni9rpNP39ZqRhnmjGX3
nyTwBJgxVFABWTBh5Vzv54BPEQFQfWB72ffRAqYStxKsobLRzDxUmzd2QzitHGJF
zZC9LXgI3UpjUOifit9TK/BHHRx+LXncqL/0qRqQbYgbKU1HiKEUeCVAkgq53Wxx
+OQudBN9Bp+X/ybAsw==
-----END CERTIFICATE-----
-----BEGIN CERTIFICATE-----
MIIDUDCCAjigAwIBAgIIGNqbINwL+g0wDQYJKoZIhvcNAQELBQAwIDEeMBwGA1UE
AxMVUGViYmxlIFJvb3QgQ0EgMmZjMjZkMCAXDTIwMDgyNzIxMDg1NVoYDzIwNTAw
ODI3MjIwODU1WjAoMSYwJAYDVQQDEx1QZWJibGUgSW50ZXJtZWRpYXRlIENBIDA3
YTY5ZDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKPKzG5/lRLbBWhp
qRcG/0Bfdfs6D6RZGQnPHVOymFkoDXMv4Nva9EGPo875Hdc6stz3a/bvGVZJd0Ud
F94QmCUspDFy0f6+VRI1UGoPpHwpRPaBmAXuuHrY8qiF/ZoNmsTPUmdlhzWGXegK
WAVTtDUaVJobXC2LEL1cWiUlb7pzIdLMODDqXM5v6dkcp/r6nvHVyV1jk56cyXVo
dvxKK7lW1E5fYgNlwU7Lp94qdnphaSIeZYcvoiBVvKxCAPW63F4SaKabxv9U+iql
Tbvep2/+2lWSrg0e6FNU7JMBw5af6ziZl0YElbRh0Es7VnTItP4W0m/VKBPEXnxn
uboViA0CAwEAAaOBgzCBgDAOBgNVHQ8BAf8EBAMCAoQwHQYDVR0lBBYwFAYIKwYB
BQUHAwEGCCsGAQUFBwMCMA8GA1UdEwEB/wQFMAMBAf8wHQYDVR0OBBYEFMaDRAKN
Q6Jh9GLvEiokSswdAu1/MB8GA1UdIwQYMBaAFJjeDmkMtjjHIRrMownx6qFHf0Qs
MA0GCSqGSIb3DQEBCwUAA4IBAQBtKwt/c/DwgGTJVwvafH/K2WMJVmos/TztNsT8
uwOGcbZV2GIM1EtBuT/0Iqdp/ICH9sRuYSfljEsUPEHtBBK6EsnK/VZb6bED0EM2
IqRXUUdx6t1mWJDLnfGllIDWmxEyUmqwMcMLEkYVg4RdZL16AmPRU1gEXmr5qY5B
8V9OQteW42Q9O3DcFkqOKuNoYZKt+FUqRKyK+azFoElDGBEtf7Nci6Tu1fICGnYs
4ps029spwvtZAh+xFaza1ScWrllQf/mA5a7/Hd3xm3WC6ho5rUtdC1NpSWh0rJGc
M6lczEk5TdIIKWGEOnqAxLwxXYa6xe+z6mr1bJMQZHuJS9sQ
-----END CERTIFICATE-----"""
    with open(certpath, "wb") as f:
        f.write(cert.encode("ASCII"))
    return certpath
