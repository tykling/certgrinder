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
    version="0.17.2",
    author="Thomas Steen Rasmussen",
    author_email="thomas@gibfest.dk",
    description="The client part of the Certgrinder project.",
    license="BSD License",
    license_file="LICENSE",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/tykling/certgrinder",
    packages=["certgrinder"],
    entry_points={"console_scripts": ["certgrinder = certgrinder.certgrinder:main"]},
    classifiers=[
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
    install_requires=["PyYAML", "dnspython", "cryptography<35", "pid"],
    include_package_data=True,
)
