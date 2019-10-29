# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Changed

- Change uniqueItems error messages, to remove Python repr blocks [cove#1220](https://github.com/OpenDataServices/cove/issues/1220)

## [0.11.0] - 2019-10-08

### Added

- Return specific validation errors for `oneOf` in OCDS records, by using the presence/absence of `id` to assume embedded/linked releases sub-schema. Only works for OCDS records. [cove#895](https://github.com/OpenDataServices/cove/issues/895)
- Add an `assumption` key to the validation JSON, to flag when one of the above assumptions has been made. [cove#895](https://github.com/OpenDataServices/cove/issues/895)
- Add an `error_id` key to the validation JSON, a machine readable ID for the error. Currently only implemented for 1 error. [#31](https://github.com/OpenDataServices/lib-cove/pull/31#issuecomment-538868533)

### Changed

- Remove restriction on jsonschema version ([commit](https://github.com/OpenDataServices/lib-cove/pull/31/commits/f23fdd332c97903e21e478146bd490898efe3995))

## [0.10.0] - 2019-09-06

### Changed

- Allow the passing of `root_id` to the conversion tool

## [0.9.0] - 2019-08-29

### Changed

- Allow the passing of `root_list_path` to the conversion tool

## [0.8.0] - 2019-08-28

### Changed

- OCDS is now available on SSL. Updated comments and tests (but no code).
- Improve CustomJsonrefLoader; make `schema_url` a required parameter.
- Improve UI for validation errors on array items.
- More tests.

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
