import setuptools

with open("README.md", "r") as fh:
    long_description = fh.read()

setuptools.setup(
    name="certgrinder-server",
    version="0.13.0",
    author="Thomas Steen Rasmussen",
    author_email="thomas@gibfest.dk",
    description="The server part of the Certgrinder project",
    license="BSD License",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/tykling/certgrinder",
    packages=["certgrinder_server"],
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: BSD License",
        "Operating System :: OS Independent",
    ],
    python_requires=">=3.7",
)