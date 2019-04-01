# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Put more data into the error JSON returned, when grouping validation errors. This will allow different CoVEs to write their own validation messages.

## [0.5.0] - 2019-03-25

### Added

- Return specific validation errors for `oneOf`, by using `statementType` to pick the correct sub-schema. Only works for BODS. [#16](https://github.com/openownership/cove-bods/issues/16)

## [0.4.0] - 2019-03-14

### Changed

- Require jsonschema version before 2.7
- Put validator type into the context https://github.com/OpenDataServices/cove/issues/1117

### Fixed
- filter_conversion_warnings in converters.py - fix deprecation of logger.warn to logger.warning.

## [0.3.1] - 2018-11-30

### Fixed

- get_file_type fix - when passed a Django file object to a JSON file without the .json extension, will detect as 'json'

## [0.3.0] - 2018-11-28

### Added

- convert_spreadsheet passes xml_comment to flatten_tool

## [0.2.1] - 2018-11-28

### Fixed

- Fix broken key names that caused problems for IATI

## [0.2.0] - 2018-11-28

### Added

- Added get_orgids_prefixes to common

## [0.1.0] - 2018-11-20

- First Release
