import os
from setuptools import setup, find_namespace_packages

import pathlib
HERE = pathlib.Path(__file__).parent


PACKAGE_NAME = "oceana_jwt_auth"
VERSION = "0.0.5"
AUTHOR = "jorgegilramos"
DESCRIPTION = "Oceana API library to manage JWT token in Flask Restx applications"
LONG_DESCRIPTION = (HERE / "README.md").read_text(encoding="utf-8")
LONG_DESC_TYPE = "text/markdown"
PROGRAMMING = "Programming Language :: Python :: 3"
LICENSE = "License :: OSI Approved :: MIT License"
OSINFO = "Operating System :: OS Independent"


def parse_requirements(filename):

    filename = f"{HERE}{os.path.sep}{filename}"
    print(f"Filename: {filename}")
    lines_iterator = (line.strip() for line in open(filename))
    return [line for line in lines_iterator if line and not (line.startswith("#") or line.startswith("-"))]


setup(
    name=PACKAGE_NAME,
    version=VERSION,
    packages=find_namespace_packages(where="src", exclude="tests"),
    package_dir={"": "src"},
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    long_description_content_type=LONG_DESC_TYPE,
    author=AUTHOR,
    license=LICENSE,
    install_requires=parse_requirements("requirements.txt"),
    extras_require={
        "develop": parse_requirements("requirements_test.txt"),
    },
    include_package_data=True,
    # tests_require=parse_requirements("requirements_test.txt")
    classifiers=[
        PROGRAMMING,
        LICENSE,
        OSINFO,
    ],
    python_requires=">= 3.9",
)
