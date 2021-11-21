# type: ignore
"""Fairly minimal certgrinder setup.py for setuptools.

Can be installed from PyPi https://pypi.org/project/certgrinder/
Read more at https://certgrinder.readthedocs.io/en/latest/certgrinder.html
"""
import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="certgrinder",
    version="0.18.0-dev",
    author="Thomas Steen Rasmussen",
    author_email="thomas@gibfest.dk",
    description="The client part of the Certgrinder project. Use with 'certgrinderd' package on the server-side.",
    license="BSD License",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/tykling/certgrinder",
    packages=["certgrinder"],
    entry_points={"console_scripts": ["certgrinder = certgrinder.certgrinder:main"]},
    classifiers=[
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
    install_requires=["PyYAML", "dnspython", "cryptography<36", "pid"],
    include_package_data=True,
)
