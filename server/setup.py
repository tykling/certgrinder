# type: ignore
"""Fairly minimal certgrinderd setup.py for setuptools.

Can be installed from PyPi https://pypi.org/project/certgrinderd/
Read more at https://certgrinder.readthedocs.io/en/latest/certgrinderd.html
"""
import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="certgrinderd",
    version="0.13.2",
    author="Thomas Steen Rasmussen",
    author_email="thomas@gibfest.dk",
    description="The server part of the Certgrinder project. Use with the 'certgrinder' client package.",
    license="BSD License",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/tykling/certgrinder",
    packages=["certgrinderd"],
    entry_points={"console_scripts": ["certgrinderd = certgrinderd.certgrinderd:main"]},
    classifiers=[
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
    install_requires=["certbot", "PyYAML"],
    include_package_data=True,
)
