# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](http://keepachangelog.com/en/1.0.0/)
and this project adheres to [Semantic Versioning](http://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.26.1] - 2021-10-01

## Changed

- Lock to jsonschema version 3 (we use internal tools that are not available in V4)

## [0.26.0] - 2021-09-15

## Changed

- Various performance improvements https://github.com/open-contracting/lib-cove-oc4ids/issues/23

## [0.25.0] - 2021-08-18

## Added

- Add a function to calculate field coverage https://github.com/open-contracting/cove-oc4ids/issues/98

## [0.24.0] - 2021-05-20

## Changed

- Update `unique_ids` override to support multiple ids. If you called `unique_ids` with `id_name="some_id"`, you now need to call `id_names=["some_id"]`. See this lib-cove-ocds PR as an example: https://github.com/open-contracting/lib-cove-ocds/pull/91/files

### Fixed

- Don't error on some decimals https://github.com/open-contracting/cove-ocds/issues/158

## [0.23.0] - 2021-05-12

### Removed

- Drop Python 3.5 support https://github.com/OpenDataServices/lib-cove/pull/81

## CHanged

- Remove unused dependencies from setup.py https://github.com/OpenDataServices/lib-cove/pull/80

## [0.22.1] - 2021-04-08

### Fixed

- Fix a typo of a variable name, that meant `date-time` and `uri` validation messages were incorrectly grouped

## [0.22.0] - 2021-02-25

### Changed

- `get_schema_validation_errors` and therefore `common_checks_context` return more fields on each error dictionary, so that we can [replace the message with a translation in lib-cove-web](https://github.com/open-contracting/cove-ocds/issues/144)

### Fixed

- Don't error when the value for the `items` key in a JSON Schema is not a dict

## [0.21.0] - 2021-02-17

### Changed

- Remove dependency on fcntl, improve Windows support https://github.com/OpenDataServices/lib-cove/pull/74

## [0.20.3] - 2021-01-20

### Fixed

- JSON Schema is not guaranteed to set `type`, so look for `properties` or `items` instead (in `schema_dict_fields_generator`)

### Fixed

## [0.20.2] - 2020-11-04

### Fixed

- Don't error when JSON schema "properties" values aren't JSON Schema, and log a warning instead https://github.com/OpenDataServices/lib-cove/pull/71

## [0.20.1] - 2020-10-27

### Fixed

- Fixes for translation work in 0.20.0 to work with [360Giving and IATI CoVEs](https://github.com/OpenDataServices/cove/)

## [0.20.0] - 2020-10-19

### Changed

- Move all strings that show in the web frontend from here to lib-cove-web. This includes HTML validation messages. https://github.com/OpenDataServices/lib-cove/pull/68

## [0.19.1] - 2020-10-08

### Fixed

- Don't require a config to be set on schema objects

## [0.19.0] - 2020-09-28

### Changed

- CustomRefResolver and CustomJsonrefLoader now respect `cache_all_requests` in the config

## [0.18.0] - 2020-08-26

### Fixed

- No longer crashes when null appears in an array https://github.com/OpenDataServices/cove/issues/1287

### Changed

- Remove OCDS specific code. This includes renaming several methods of SchemaJsonMixin to remove the word "release". Any use of this mixin will need to be updated. This includes OCDS, 360Giving, IATI and BODS CoVEs.

## [0.17.0] - 2020-04-23

### Changed

- Update Django to 2.2 LTS

## [0.16.1] - 2020-03-19

### Note

- v0.16.0 was tagged too early. 

### Fixed

- Fix grouping of validation errors https://github.com/OpenDataServices/cove/issues/1225

## [0.15.0] - 2020-02-24

- Accept .ods format

## [0.14.0] - 2020-02-13

### Added

- Depend on rfc3987 and strict-rfc3339 (optional dependencies of jsonschema) in order to validate URIs and date-times correctly [lib-cove-bods#54](https://github.com/openownership/lib-cove-bods/pull/54#issuecomment-585303356)

## [0.13.0] - 2020-01-09

### Added

- Extend new oneOf validation messages to OCDS 1.0 files [cove#895](https://github.com/OpenDataServices/cove/issues/895#issuecomment-558721218)

### Changed

- Update Django and flatten-tool versions.

## [0.12.2] - 2019-11-26

### Fixed

- Fix uniqueItems error messages — don't report duplication where there isn't any [cove#1246](https://github.com/OpenDataServices/cove/issues/1246)

## [0.12.1] - 2019-11-25

### Fixed

- Attempt to fix uniqueItems error messages, but accidentally report duplicates when there aren't any, and not when there are (fixed in 0.12.2) [cove#1246](https://github.com/OpenDataServices/cove/issues/1246)

## [0.12.0] - 2019-10-29

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
