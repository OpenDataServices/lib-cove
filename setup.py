from setuptools import find_packages, setup

setup(
    name="libcove",
    version="0.32.0",
    author="Open Data Services",
    author_email="code@opendataservices.coop",
    url="https://github.com/OpenDataServices/lib-cove",
    description="A data review library",
    packages=find_packages(),
    long_description="A data review library",
    install_requires=[
        "jsonref",
        "jsonschema>=4.18",
        "referencing",
        "requests",
        "cached-property;python_version<'3.8'",
        "flattentool>=0.11.0",
        # Required for jsonschema to validate URIs
        "rfc3987",
        # Required for jsonschema to validate date-time
        "rfc3339-validator",
    ],
    classifiers=[
        "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)"
    ],
)
