# type: ignore
import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="certgrinder",
    version="0.13.0-alpha",
    author="Thomas Steen Rasmussen",
    author_email="thomas@gibfest.dk",
    description="The client part of the Certgrinder project. Use with 'certgrinderd' package on the serverside.",
    license="BSD License",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/tykling/certgrinder",
    packages=["certgrinder"],
    scripts=["certgrinder/certgrinder.py"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
    install_requires=["PyYAML", "dnspython", "cryptography", "pid"],
)
