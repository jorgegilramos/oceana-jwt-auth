import os
import io
import re

from setuptools import setup, find_namespace_packages

import pathlib
HERE = pathlib.Path(__file__).parent


PACKAGE_NAME = "oceana_jwt_auth"
AUTHOR = "jorgegilramos"
DESCRIPTION = "Oceana API library to manage JWT token in Flask Restx applications"
LONG_DESCRIPTION = (HERE / "README.md").read_text(encoding="utf-8")
LONG_DESC_TYPE = "text/markdown"


with io.open("src/oceana_jwt_auth/__init__.py", encoding="utf-8") as f:
    version = re.search(r"__version__ = \"(.+)\"", f.read()).group(1)


def parse_requirements(filename):

    filename = f"{HERE}{os.path.sep}{filename}"
    print(f"Filename: {filename}")
    lines_iterator = (line.strip() for line in open(filename))
    return [line for line in lines_iterator if line and not (line.startswith("#") or line.startswith("-"))]


setup(
    name=PACKAGE_NAME,
    version=version,
    url="https://github.com/jorgegilramos/oceana-jwt-auth",
    packages=find_namespace_packages(where="src", exclude="tests"),
    package_dir={"": "src"},
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    long_description_content_type=LONG_DESC_TYPE,
    author=AUTHOR,
    # SetuptoolsWarning: `license` overwritten by `pyproject.toml`
    # license="MIT",
    # SetuptoolsWarning: `install_requires` overwritten in `pyproject.toml` (dependencies)
    # install_requires=parse_requirements("requirements.txt"),
    # extras_require={
    #     "develop": parse_requirements("requirements_develop.txt"),
    # },
    include_package_data=True,
    # tests_require=parse_requirements("requirements_test.txt")
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Environment :: Web Environment",
        "Intended Audience :: Developers",
        "Operating System :: MacOS :: MacOS X",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: POSIX",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Operating System :: OS Independent",
        "Topic :: Software Development",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "Topic :: Internet :: WWW/HTTP :: HTTP Servers",
        "Topic :: Internet :: WWW/HTTP :: WSGI :: Application",
        "Topic :: Security",
        "Framework :: Flask",
        # "License :: OSI Approved :: MIT License"
    ],
    python_requires=">= 3.12",
)
