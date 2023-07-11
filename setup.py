from setuptools import find_packages, setup

setup(
    name="libcove",
    version="0.31.0",
    author="Open Data Services",
    author_email="code@opendataservices.coop",
    url="https://github.com/OpenDataServices/lib-cove",
    description="A data review library",
    packages=find_packages(),
    long_description="A data review library",
    install_requires=[
        "jsonref",
        "jsonschema>=3",
        "requests",
        "cached-property;python_version<'3.8'",
        # Required for jsonschema to validate URIs
        "rfc3987",
        # Required for jsonschema to validate date-time
        "rfc3339-validator",
    ],
    extras_require={
        "flatten": [
            "flattentool>=0.11.0",
        ],
    },
    classifiers=[
        "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)"
    ],
)
