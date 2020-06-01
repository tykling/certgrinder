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

    print("Beginning teardown")
    print("Stopping pebble server...")
    proc.terminate()
    print("Teardown finished!")


@pytest.fixture
def certgrinderd_broken_yaml_configfile(tmp_path_factory):
    """Write a certgrinderd.yml file with invalid yml."""
    confpath = tmp_path_factory.mktemp("conf") / "certgrinderd.yml"
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
        "acme-server-url": "https://127.0.0.1:14000/dir",
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
    else:
        raise ValueError("Unsupported auth type")
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
