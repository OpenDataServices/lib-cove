import json
import os
from collections import OrderedDict
from libcove.lib.common import SchemaJsonMixin, \
    get_json_data_generic_paths, get_json_data_deprecated_fields, get_fields_present, \
    _get_schema_deprecated_paths, schema_dict_fields_generator, fields_present_generator, get_orgids_prefixes, \
    get_additional_fields_info, get_schema_validation_errors


def test_get_json_data_deprecated_fields():
    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'fixtures', 'common',
                           'tenders_releases_2_releases_with_deprecated_fields.json')) as fp:  # noqa
        json_data_w_deprecations = json.load(fp)

    schema_obj = SchemaJsonMixin()
    schema_obj.schema_host = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'fixtures', 'common/')
    schema_obj.release_pkg_schema_name = 'release_package_schema_ref_release_schema_deprecated_fields.json'
    schema_obj.release_pkg_schema_url = os.path.join(schema_obj.schema_host, schema_obj.release_pkg_schema_name)
    json_data_paths = get_json_data_generic_paths(json_data_w_deprecations)
    deprecated_data_fields = get_json_data_deprecated_fields(json_data_paths, schema_obj)
    expected_result = OrderedDict([
        ('initiationType', {"paths": ('releases/0', 'releases/1'),
                            "explanation": ('1.1', 'Not a useful field as always has to be tender')}),
        ('quantity', {"paths": ('releases/0/tender/items/0',),
                      "explanation": ('1.1', 'Nobody cares about quantities')})
    ])
    for field_name in expected_result.keys():
        assert field_name in deprecated_data_fields
        assert expected_result[field_name]["paths"] == deprecated_data_fields[field_name]["paths"]
        assert expected_result[field_name]["explanation"] == deprecated_data_fields[field_name]["explanation"]


def test_fields_present_1():
    assert get_fields_present({}) == {}


def test_fields_present_2():
    assert get_fields_present({'a': 1, 'b': 2}) == {"/a": 1, "/b": 1}


def test_fields_present_3():
    assert get_fields_present({'a': {}, 'b': 2}) == {'/a': 1, '/b': 1}


def test_fields_present_4():
    assert get_fields_present({'a': {'c': 1}, 'b': 2}) == {'/a': 1, '/b': 1, '/a/c': 1}


def test_fields_present_5():
    assert get_fields_present({'a': {'c': 1}, 'b': 2}) == {'/a': 1, '/b': 1, '/a/c': 1}


def test_fields_present_6():
    assert get_fields_present({'a': {'c': {'d': 1}}, 'b': 2}) == {'/a': 1, '/b': 1, '/a/c': 1, '/a/c/d': 1}


def test_fields_present_7():
    assert get_fields_present({'a': [{'c': 1}], 'b': 2}) == {'/a': 1, '/b': 1, '/a/c': 1}


def test_fields_present_8():
    assert get_fields_present({'a': {'c': [{'d': 1}]}, 'b': 2}) == {'/a': 1, '/b': 1, '/a/c': 1, '/a/c/d': 1}


def test_fields_present_9():
    assert get_fields_present({'a': {'c_1': [{'d': 1}]}, 'b_1': 2}) == {'/a': 1, '/a/c_1': 1, '/a/c_1/d': 1, '/b_1': 1}


def test_fields_present_10():
    assert get_fields_present({'a': {'c_1': [{'d': 1}, {'d': 1}]}, 'b_1': 2}) == {'/a': 1, '/a/c_1': 1, '/a/c_1/d': 2, '/b_1': 1} # noqa


def test_get_schema_deprecated_paths():
    schema_obj = SchemaJsonMixin()
    schema_obj.schema_host = os.path.join(os.path.dirname(os.path.realpath(__file__)), 'fixtures', 'common/')
    schema_obj.release_pkg_schema_name = 'release_package_schema_ref_release_schema_deprecated_fields.json'
    schema_obj.release_pkg_schema_url = os.path.join(schema_obj.schema_host, schema_obj.release_pkg_schema_name)
    deprecated_paths = _get_schema_deprecated_paths(schema_obj)
    expected_results = [
        (('releases', 'initiationType'), ('1.1', 'Not a useful field as always has to be tender')),
        (('releases', 'planning',), ('1.1', "Testing deprecation for objects with '$ref'")),
        (('releases', 'tender', 'hasEnquiries'), ('1.1', 'Deprecated just for fun')),
        (('releases', 'contracts', 'items', 'quantity'), ('1.1', 'Nobody cares about quantities')),
        (('releases', 'tender', 'items', 'quantity'), ('1.1', 'Nobody cares about quantities')),
        (('releases', 'awards', 'items', 'quantity'), ('1.1', 'Nobody cares about quantities'))
    ]
    assert len(deprecated_paths) == 6
    for path in expected_results:
        assert path in deprecated_paths


def test_schema_dict_fields_generator_release_schema_deprecated_fields():

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'fixtures', 'common',
                           'release_schema_deprecated_fields.json')) as fp:  # noqa
        json_schema = json.load(fp)

    data = sorted(set(schema_dict_fields_generator(json_schema)))

    assert 11 == len(data)

    assert data[0] == '/awards'
    assert data[1] == '/buyer'
    assert data[2] == '/contracts'
    assert data[3] == '/date'
    assert data[4] == '/id'
    assert data[5] == '/initiationType'
    assert data[6] == '/language'
    assert data[7] == '/ocid'
    assert data[8] == '/planning'
    assert data[9] == '/tag'
    assert data[10] == '/tender'


def test_schema_dict_fields_generator_schema_with_list_and_oneof():

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'fixtures', 'common',
                           'schema_with_list_and_oneof.json')) as fp:  # noqa
        json_schema = json.load(fp)

    data = sorted(set(schema_dict_fields_generator(json_schema)))

    assert data == ['/dissolutionDate', '/entityType', '/names', '/names/familyName', '/names/fullName',
                    '/names/givenName', '/names/patronymicName', '/names/type', '/source', '/source/assertedBy',
                    '/source/assertedBy/name', '/source/assertedBy/uri', '/source/description', '/source/retrievedAt',
                    '/source/type', '/source/url']


def test_fields_present_generator_tenders_releases_2_releases():

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'fixtures', 'common',
                           'tenders_releases_2_releases.json')) as fp:  # noqa
        json_schema = json.load(fp)

    data = sorted(set(key for key, _ in fields_present_generator(json_schema)))

    assert data == ['/license', '/publishedDate', '/publisher', '/publisher/name', '/publisher/scheme',
                    '/publisher/uid',
                    '/publisher/uri', '/releases', '/releases/buyer', '/releases/buyer/name', '/releases/date',
                    '/releases/id',
                    '/releases/initiationType', '/releases/language', '/releases/ocid', '/releases/tag',
                    '/releases/tender',
                    '/releases/tender/awardCriteriaDetails', '/releases/tender/documents',
                    '/releases/tender/documents/id',
                    '/releases/tender/documents/url', '/releases/tender/id', '/releases/tender/items',
                    '/releases/tender/items/classification', '/releases/tender/items/classification/description',
                    '/releases/tender/items/classification/scheme', '/releases/tender/items/description',
                    '/releases/tender/items/id',
                    '/releases/tender/methodRationale', '/releases/tender/procuringEntity',
                    '/releases/tender/procuringEntity/name',
                    '/releases/tender/procuringEntity/name_fr', '/releases/tender/tenderPeriod',
                    '/releases/tender/tenderPeriod/endDate', '/uri']


def test_fields_present_generator_data_root_is_list():

    with open(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'fixtures', 'common',
                           'data_root_is_list.json')) as fp:  # noqa
        json_schema = json.load(fp)

    data = sorted(set(key for key, _ in fields_present_generator(json_schema)))

    assert data == ['/addresses', '/addresses/address', '/addresses/country', '/addresses/postCode', '/addresses/type',
                    '/birthDate', '/entityType', '/foundingDate', '/identifiers', '/identifiers/id',
                    '/identifiers/scheme', '/interestedParty', '/interestedParty/describedByPersonStatement',
                    '/interests', '/interests/beneficialOwnershipOrControl', '/interests/interestLevel',
                    '/interests/share', '/interests/share/exact', '/interests/startDate', '/interests/type', '/name',
                    '/names', '/names/familyName', '/names/fullName', '/names/givenName', '/names/type',
                    '/nationalities', '/nationalities/code', '/personType', '/statementDate', '/statementID',
                    '/statementType', '/subject', '/subject/describedByEntityStatement']


def test_get_additional_fields_info():

    simple_data = {
        "non_additional_field": "a",
        "non_additional_list": [1, 2],
        "non_additional_object": {"z": "z"},
        "additional_object": {"a": "a", "b": "b"},
        "additional_list": [{"c": "c", "d": "d"}, {"e": "e", "f": "f"}, {"e": "e", "f": "f"}]
    }

    schema_fields = {"/non_additional_field", "/non_additional_list",
                     "/non_additional_object", "/non_additional_object/z"}

    additional_field_info = get_additional_fields_info(json_data=simple_data,
                                                       schema_fields=schema_fields,
                                                       context={})
    assert len(additional_field_info) == 8
    assert sum(info['count'] for info in additional_field_info.values()) == 10
    assert len([info for info in additional_field_info.values() if info['root_additional_field']]) == 2


def test_get_orgids_prefixes_live():
    data = get_orgids_prefixes()

    # There is not much we can really test here, as the results will depend on the live data!
    assert len(data) > 150


class DummyRecordSchemaObj:
    def __init__(self, schema_host):
        self.schema_host = schema_host

    def get_record_pkg_schema_obj(self):
        with open(os.path.join(self.schema_host, "record-package-schema.json")) as fp:
            schema_json = json.load(fp)
        return schema_json


def test_validation_invalid_record_package():
    filename = "records_invalid_releases.json"

    schema_host = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "fixtures", "common", ""
    )
    with open(os.path.join(schema_host, filename)) as fp:
        invalid_record_package = json.load(fp)

    validation_errors = get_schema_validation_errors(
        invalid_record_package,
        DummyRecordSchemaObj(schema_host),
        "record-package-schema.json",
        {},
        {},
    )

    validation_error_jsons = []
    for validation_error_json, values in sorted(validation_errors.items()):
        validation_error_json = json.loads(validation_error_json)
        validation_error_json["values"] = values
        # Remove this as it can be a rather large schema object
        del validation_error_json["validator_value"]
        validation_error_jsons.append(validation_error_json)

    assert validation_error_jsons == [
        {
            "message": "'date' is missing but required within 'releases'",
            "message_safe": "<code>date</code> is missing but required within <code>releases</code>",
            "validator": "required",
            "assumption": "embedded_releases",
            "message_type": "required",
            "path_no_number": "records/releases",
            "header": "date",
            "header_extra": "releases/0",
            "null_clause": "",
            "values": [{"path": "records/2/releases/0"}],
        },
        {
            "message": "'date' is missing but required within 'releases'",
            "message_safe": "<code>date</code> is missing but required within <code>releases</code>",
            "validator": "required",
            "assumption": "linked_releases",
            "message_type": "required",
            "path_no_number": "records/releases",
            "header": "date",
            "header_extra": "releases/0",
            "null_clause": "",
            "values": [
                {"path": "records/1/releases/0"},
                {"path": "records/3/releases/0"},
            ],
        },
        {
            "message": "'initiationType' is missing but required within 'releases'",
            "message_safe": "<code>initiationType</code> is missing but required within <code>releases</code>",
            "validator": "required",
            "assumption": "embedded_releases",
            "message_type": "required",
            "path_no_number": "records/releases",
            "header": "initiationType",
            "header_extra": "releases/0",
            "null_clause": "",
            "values": [{"path": "records/2/releases/0"}],
        },
        {
            "message": "'ocid' is missing but required within 'releases'",
            "message_safe": "<code>ocid</code> is missing but required within <code>releases</code>",
            "validator": "required",
            "assumption": "embedded_releases",
            "message_type": "required",
            "path_no_number": "records/releases",
            "header": "ocid",
            "header_extra": "releases/0",
            "null_clause": "",
            "values": [{"path": "records/2/releases/0"}],
        },
        {
            "message": "'releases' is not a JSON array",
            "message_safe": "<code>releases</code> is not a JSON array",
            "validator": "type",
            "assumption": "linked_releases",
            "message_type": "array",
            "path_no_number": "records/releases",
            "header": "releases",
            "header_extra": "releases",
            "null_clause": "is not null, and",
            "values": [
                {"path": "records/6/releases", "value": "a string"},
                {"path": "records/7/releases", "value": None},
                {"path": "records/8/releases"},
            ],
        },
        {
            "message": "'tag' is missing but required within 'releases'",
            "message_safe": "<code>tag</code> is missing but required within <code>releases</code>",
            "validator": "required",
            "assumption": "embedded_releases",
            "message_type": "required",
            "path_no_number": "records/releases",
            "header": "tag",
            "header_extra": "releases/0",
            "null_clause": "",
            "values": [{"path": "records/2/releases/0"}],
        },
        {
            "message": "'url' is missing but required within 'releases'",
            "message_safe": "<code>url</code> is missing but required within <code>releases</code>",
            "validator": "required",
            "assumption": "linked_releases",
            "message_type": "required",
            "path_no_number": "records/releases",
            "header": "url",
            "header_extra": "releases/0",
            "null_clause": "",
            "values": [{"path": "records/1/releases/0"}],
        },
        {
            "message": "This array should contain either entirely embedded releases or linked releases. "
                       "Embedded releases contain an 'id' whereas linked releases do not. "
                       "Your releases contain a mixture.",
            "message_safe": "This array should contain either entirely embedded releases or linked releases. "
                            "Embedded releases contain an &#39;id&#39; whereas linked releases do not. "
                            "Your releases contain a mixture.",
            "validator": "oneOf",
            "assumption": None,
            "message_type": "oneOf",
            "path_no_number": "records/releases",
            "header": "releases",
            "header_extra": "releases",
            "null_clause": "",
            "values": [{"path": "records/4/releases"}, {"path": "records/5/releases"}],
        },
        {
            "message": "[] is too short",
            "message_safe": "<code>[]</code> is too short. "
                            "You must supply at least one value, or remove the item entirely (unless it’s required).",
            "validator": "minItems",
            "assumption": "linked_releases",
            "message_type": "minItems",
            "path_no_number": "records/releases",
            "header": "releases",
            "header_extra": "releases",
            "null_clause": "",
            "values": [{"path": "records/0/releases"}],
        },
    ]
