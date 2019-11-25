from setuptools import find_packages, setup

setup(
    name="libcove",
    version="0.12.1",
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
        "Django",
        "bleach",
        "requests",
        "json-merge-patch",
        "cached-property",
        # TODO Should also have flatten-tool >= v0.5.0 - that is currently in requirements instead.
    ],
    classifiers=[
        "License :: OSI Approved :: GNU Affero General Public License v3 or later (AGPLv3+)"
    ],
)
