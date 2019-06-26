# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.7.1] - 2019-06-26

### Changed

- OCDS is now available on SSL. Updated comments and tests (but no code)
- Fixed syntax error bug in tools module

## [0.7.0] - 2019-06-06

### Added

- Add new additional fields section to context which list all additional fields.  It also states which are top level additional fields with all their descendants.

## [0.6.0] - 2019-04-12

### Added

- cache_all_requests config option, off by default
  - New function libcove.tools.get_request(). Pass it a config and it will use cache_all_requests option to decide whether to cache or not. (Also has force_cache option)
  - load_codelist function now takes a config option, and will cache requests if set (Uses new get_request function)
  - load_core_codelists function now takes a config option, and will cache requests if set.
  - SchemaJsonMixin will check a config varible in the class as well as cache_schema variable (Uses new get_request function)

### Changed

- Put more data into the error JSON returned, when grouping validation errors. This will allow different CoVEs to write their own validation messages. [#14](https://github.com/OpenDataServices/lib-cove/pull/14)

## [0.5.0] - 2019-03-25

### Added

- Return specific validation errors for `oneOf`, by using `statementType` to pick the correct sub-schema. Only works for BODS. [cove-bods#16](https://github.com/openownership/cove-bods/issues/16)

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
