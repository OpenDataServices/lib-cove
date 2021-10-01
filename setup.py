from setuptools import find_packages, setup

setup(
    name="libcove",
    version="0.26.1",
    author="Open Data Services",
    author_email="code@opendataservices.coop",
    url="https://github.com/OpenDataServices/lib-cove",
    description="A data review library",
    packages=find_packages(),
    long_description="A data review library",
    install_requires=[
        "jsonref",
        "jsonschema>=3,<4",
        "requests",
        "cached-property",
        "flattentool>=0.11.0",
        # Required for jsonschema to validate URIs
        "rfc3987",
        # Required for jsonschema to validate date-time
        "strict-rfc3339",
    ],
    classifiers=[
        "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)"
    ],
)
