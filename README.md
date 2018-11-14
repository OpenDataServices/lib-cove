# Lib Cove OCDS

## Command line

Call `libcoveocds` and pass the filename of some JSON data.

    libcoveocds tests/fixtures/common_checks/basic_1.json

## Code for use by external users

The only code that should be used directly by users is the `libcoveocds.config` and `libcoveocds.api` modules.

Other code ( Code in `libcore`, `lib`, etc) 
should not be used by external users of this library directly, as the structure and use of these may change more frequently.
