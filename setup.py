from setuptools import find_packages, setup

setup(
    name="libcove",
    version="0.13.0",
    author="Open Data Services",
    author_email="code@opendataservices.coop",
    url="https://github.com/OpenDataServices/lib-cove",
    description="A data review library",
    packages=find_packages(),
    long_description="A data review library",
    install_requires=[
        "jsonref",
        "jsonschema",
        "CommonMark",
        "Django>=1.11.23,<1.12",
        "bleach",
        "requests",
        "json-merge-patch",
        "cached-property",
        "flattentool>=0.5.0",
    ],
    classifiers=[
        "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)"
    ],
)
