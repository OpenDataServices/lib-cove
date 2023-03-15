import json
import os
from datetime import datetime
from decimal import Decimal
from unittest import mock

import jsonschema
import pytest
from freezegun import freeze_time

from libcove.lib.common import (
    SchemaJsonMixin,
    _get_schema_deprecated_paths,
    add_field_coverage,
    add_field_coverage_percentages,
    fields_present_generator,
    get_additional_codelist_values,
    get_additional_fields_info,
    get_field_coverage,
    get_fields_present,
    get_json_data_deprecated_fields,
    get_json_data_generic_paths,
    get_orgids_prefixes,
    get_schema_validation_errors,
    org_id_file_fresh,
    schema_dict_fields_generator,
    unique_ids,
)


def test_unique_ids_False():
    ui = False
    schema = {"uniqueItems": ui}
    validator = jsonschema.Draft4Validator(schema=schema)
    assert list(unique_ids(validator, ui, [], schema)) == []
    assert list(unique_ids(validator, ui, [{}, {}], schema)) == []
    assert list(unique_ids(validator, ui, [{"id": "1"}, {"id": "2"}], schema)) == []
    assert list(unique_ids(validator, ui, [{"id": "1"}, {"id": 1}], schema)) == []


def test_unique_ids_True():
    ui = True
    schema = {"uniqueItems": ui}
    validator = jsonschema.Draft4Validator(schema=schema)
    # If all items are unique, there should be no errors
    assert list(unique_ids(validator, ui, [], schema)) == []
    assert list(unique_ids(validator, ui, [], schema, id_names=["id"])) == []
    assert list(unique_ids(validator, ui, [], schema, id_names=["ocid"])) == []
    assert list(unique_ids(validator, ui, [], schema, id_names=["ocid", "id"])) == []
    assert list(unique_ids(validator, ui, [{"id": "1"}, {"id": "2"}], schema)) == []
    assert (
        list(
            unique_ids(
                validator, ui, [{"id": "1"}, {"id": "2"}], schema, id_names=["id"]
            )
        )
        == []
    )
    assert (
        list(
            unique_ids(
                validator, ui, [{"id": "1"}, {"id": "2"}], schema, id_names=["ocid"]
            )
        )
        == []
    )
    assert (
        list(
            unique_ids(
                validator,
                ui,
                [{"id": "1"}, {"id": "2"}],
                schema,
                id_names=["ocid", "id"],
            )
        )
        == []
    )
    assert list(unique_ids(validator, ui, [], schema, id_names=["ocid", "id"])) == []
    # If id is the same, but ocid is different, then we should get no errors
    assert (
        list(
            unique_ids(
                validator,
                ui,
                [{"ocid": "1", "id": "1"}, {"ocid": "2", "id": "1"}],
                schema,
                id_names=["ocid", "id"],
            )
        )
        == []
    )

    def validation_errors_to_tuples(validation_errors):
        return [
            (str(validation_error), validation_error.error_id)
            for validation_error in validation_errors
        ]

    validation_errors_to_tuples(unique_ids(validator, ui, [{}, {}], schema)) == [
        ("Array has non-unique elements", "uniqueItems_no_ids")
    ]
    assert validation_errors_to_tuples(
        unique_ids(validator, ui, [{"id": ""}, {"id": ""}], schema)
    ) == [("Non-unique id values", "uniqueItems_with_id")]
    assert validation_errors_to_tuples(
        unique_ids(validator, ui, [{"id": "1"}, {"id": "1"}], schema)
    ) == [("Non-unique id values", "uniqueItems_with_id")]
    assert validation_errors_to_tuples(
        unique_ids(validator, ui, [{"id": 1}, {"id": 1}], schema)
    ) == [("Non-unique id values", "uniqueItems_with_id")]

    assert validation_errors_to_tuples(
        unique_ids(validator, ui, [{}, {}], schema, id_names=["id"])
    ) == [("Array has non-unique elements", "uniqueItems_no_ids")]
    assert validation_errors_to_tuples(
        unique_ids(validator, ui, [{"id": ""}, {"id": ""}], schema, id_names=["id"])
    ) == [("Non-unique id values", "uniqueItems_with_id")]
    assert validation_errors_to_tuples(
        unique_ids(
            validator,
            ui,
            [{"id": "1", "other": "a"}, {"id": "1", "other": "b"}],
            schema,
            id_names=["id"],
        )
    ) == [("Non-unique id values", "uniqueItems_with_id")]

    assert validation_errors_to_tuples(
        unique_ids(validator, ui, [{}, {}], schema, id_names=["ocid"])
    ) == [("Array has non-unique elements", "uniqueItems_no_ids")]
    assert validation_errors_to_tuples(
        unique_ids(
            validator, ui, [{"ocid": ""}, {"ocid": ""}], schema, id_names=["ocid"]
        )
    ) == [("Non-unique ocid values", "uniqueItems_with_ocid")]
    assert validation_errors_to_tuples(
        unique_ids(
            validator,
            ui,
            [{"ocid": "1", "other": "a"}, {"ocid": "1", "other": "b"}],
            schema,
            id_names=["ocid"],
        )
    ) == [("Non-unique ocid values", "uniqueItems_with_ocid")]

    assert validation_errors_to_tuples(
        unique_ids(validator, ui, [{}, {}], schema, id_names=["ocid", "id"])
    ) == [("Array has non-unique elements", "uniqueItems_no_ids")]
    # If only one of the id names is present, then we get the generic message
    assert validation_errors_to_tuples(
        unique_ids(
            validator,
            ui,
            [{"ocid": "1"}, {"ocid": "1"}],
            schema,
            id_names=["ocid", "id"],
        )
    ) == [("Array has non-unique elements", "uniqueItems_no_ids")]
    assert validation_errors_to_tuples(
        unique_ids(
            validator, ui, [{"id": "1"}, {"id": "1"}], schema, id_names=["ocid", "id"]
        )
    ) == [("Array has non-unique elements", "uniqueItems_no_ids")]
    assert validation_errors_to_tuples(
        unique_ids(
            validator,
            ui,
            [
                {"ocid": "1", "id": "1", "other": "a"},
                {"ocid": "1", "id": "1", "other": "b"},
            ],
            schema,
            id_names=["ocid", "id"],
        )
    ) == [("Non-unique combination of ocid, id values", "uniqueItems_with_ocid__id")]


def test_get_json_data_deprecated_fields():
    with open(
        os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "fixtures",
            "common",
            "tenders_releases_2_releases_with_deprecated_fields.json",
        )
    ) as fp:
        json_data_w_deprecations = json.load(fp)

    schema_obj = SchemaJsonMixin()
    schema_obj.schema_host = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "fixtures", "common/"
    )
    schema_obj.release_pkg_schema_name = (
        "release_package_schema_ref_release_schema_deprecated_fields.json"
    )
    schema_obj.pkg_schema_url = os.path.join(
        schema_obj.schema_host, schema_obj.release_pkg_schema_name
    )
    json_data_paths = get_json_data_generic_paths(
        json_data_w_deprecations, generic_paths={}
    )
    deprecated_data_fields = get_json_data_deprecated_fields(
        json_data_paths, schema_obj
    )
    expected_result = {
        "initiationType": {
            "paths": ("releases/0", "releases/1"),
            "explanation": (
                "1.1",
                "Not a useful field as always has to be tender",
            ),
        },
        "quantity": {
            "paths": ("releases/0/tender/items/0",),
            "explanation": ("1.1", "Nobody cares about quantities"),
        },
    }
    for field_name in expected_result.keys():
        assert field_name in deprecated_data_fields
        assert (
            expected_result[field_name]["paths"]
            == deprecated_data_fields[field_name]["paths"]
        )
        assert (
            expected_result[field_name]["explanation"]
            == deprecated_data_fields[field_name]["explanation"]
        )


def test_fields_present_1():
    assert get_fields_present({}) == {}


def test_fields_present_2():
    assert get_fields_present({"a": 1, "b": 2}) == {"/a": 1, "/b": 1}


def test_fields_present_3():
    assert get_fields_present({"a": {}, "b": 2}) == {"/a": 1, "/b": 1}


def test_fields_present_4():
    assert get_fields_present({"a": {"c": 1}, "b": 2}) == {"/a": 1, "/b": 1, "/a/c": 1}


def test_fields_present_5():
    assert get_fields_present({"a": {"c": 1}, "b": 2}) == {"/a": 1, "/b": 1, "/a/c": 1}


def test_fields_present_6():
    assert get_fields_present({"a": {"c": {"d": 1}}, "b": 2}) == {
        "/a": 1,
        "/b": 1,
        "/a/c": 1,
        "/a/c/d": 1,
    }


def test_fields_present_7():
    assert get_fields_present({"a": [{"c": 1}], "b": 2}) == {
        "/a": 1,
        "/b": 1,
        "/a/c": 1,
    }


def test_fields_present_8():
    assert get_fields_present({"a": {"c": [{"d": 1}]}, "b": 2}) == {
        "/a": 1,
        "/b": 1,
        "/a/c": 1,
        "/a/c/d": 1,
    }


def test_fields_present_9():
    assert get_fields_present({"a": {"c_1": [{"d": 1}]}, "b_1": 2}) == {
        "/a": 1,
        "/a/c_1": 1,
        "/a/c_1/d": 1,
        "/b_1": 1,
    }


def test_fields_present_10():
    assert get_fields_present({"a": {"c_1": [{"d": 1}, {"d": 1}]}, "b_1": 2}) == {
        "/a": 1,
        "/a/c_1": 1,
        "/a/c_1/d": 2,
        "/b_1": 1,
    }


def test_get_schema_deprecated_paths():
    schema_obj = SchemaJsonMixin()
    schema_obj.schema_host = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "fixtures", "common/"
    )
    schema_obj.release_pkg_schema_name = (
        "release_package_schema_ref_release_schema_deprecated_fields.json"
    )
    schema_obj.pkg_schema_url = os.path.join(
        schema_obj.schema_host, schema_obj.release_pkg_schema_name
    )
    deprecated_paths = _get_schema_deprecated_paths(schema_obj)
    expected_results = [
        (
            ("releases", "initiationType"),
            ("1.1", "Not a useful field as always has to be tender"),
        ),
        (
            ("releases", "planning"),
            ("1.1", "Testing deprecation for objects with '$ref'"),
        ),
        (("releases", "tender", "hasEnquiries"), ("1.1", "Deprecated just for fun")),
        (
            ("releases", "contracts", "items", "quantity"),
            ("1.1", "Nobody cares about quantities"),
        ),
        (
            ("releases", "tender", "items", "quantity"),
            ("1.1", "Nobody cares about quantities"),
        ),
        (
            ("releases", "awards", "items", "quantity"),
            ("1.1", "Nobody cares about quantities"),
        ),
    ]
    assert len(deprecated_paths) == 6
    for path in expected_results:
        assert path in deprecated_paths


def test_schema_dict_fields_generator_release_schema_deprecated_fields():

    with open(
        os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "fixtures",
            "common",
            "release_schema_deprecated_fields.json",
        )
    ) as fp:
        json_schema = json.load(fp)

    data = sorted(set(schema_dict_fields_generator(json_schema)))

    assert 11 == len(data)

    assert data[0] == "/awards"
    assert data[1] == "/buyer"
    assert data[2] == "/contracts"
    assert data[3] == "/date"
    assert data[4] == "/id"
    assert data[5] == "/initiationType"
    assert data[6] == "/language"
    assert data[7] == "/ocid"
    assert data[8] == "/planning"
    assert data[9] == "/tag"
    assert data[10] == "/tender"


def test_schema_dict_fields_generator_schema_with_list_and_oneof():

    with open(
        os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "fixtures",
            "common",
            "schema_with_list_and_oneof.json",
        )
    ) as fp:
        json_schema = json.load(fp)

    data = sorted(set(schema_dict_fields_generator(json_schema)))

    assert data == [
        "/dissolutionDate",
        "/entityType",
        "/names",
        "/names/familyName",
        "/names/fullName",
        "/names/givenName",
        "/names/patronymicName",
        "/names/type",
        "/source",
        "/source/assertedBy",
        "/source/assertedBy/name",
        "/source/assertedBy/uri",
        "/source/description",
        "/source/retrievedAt",
        "/source/type",
        "/source/url",
    ]


def test_fields_present_generator_tenders_releases_2_releases():

    with open(
        os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "fixtures",
            "common",
            "tenders_releases_2_releases.json",
        )
    ) as fp:
        json_schema = json.load(fp)

    data = sorted(set(key for key, _ in fields_present_generator(json_schema)))

    assert data == [
        "/license",
        "/publishedDate",
        "/publisher",
        "/publisher/name",
        "/publisher/scheme",
        "/publisher/uid",
        "/publisher/uri",
        "/releases",
        "/releases/buyer",
        "/releases/buyer/name",
        "/releases/date",
        "/releases/id",
        "/releases/initiationType",
        "/releases/language",
        "/releases/ocid",
        "/releases/tag",
        "/releases/tender",
        "/releases/tender/awardCriteriaDetails",
        "/releases/tender/documents",
        "/releases/tender/documents/id",
        "/releases/tender/documents/url",
        "/releases/tender/id",
        "/releases/tender/items",
        "/releases/tender/items/classification",
        "/releases/tender/items/classification/description",
        "/releases/tender/items/classification/scheme",
        "/releases/tender/items/description",
        "/releases/tender/items/id",
        "/releases/tender/methodRationale",
        "/releases/tender/procuringEntity",
        "/releases/tender/procuringEntity/name",
        "/releases/tender/procuringEntity/name_fr",
        "/releases/tender/tenderPeriod",
        "/releases/tender/tenderPeriod/endDate",
        "/uri",
    ]


def test_fields_present_generator_data_root_is_list():

    with open(
        os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "fixtures",
            "common",
            "data_root_is_list.json",
        )
    ) as fp:
        json_schema = json.load(fp)

    data = sorted(set(key for key, _ in fields_present_generator(json_schema)))

    assert data == [
        "/addresses",
        "/addresses/address",
        "/addresses/country",
        "/addresses/postCode",
        "/addresses/type",
        "/birthDate",
        "/entityType",
        "/foundingDate",
        "/identifiers",
        "/identifiers/id",
        "/identifiers/scheme",
        "/interestedParty",
        "/interestedParty/describedByPersonStatement",
        "/interests",
        "/interests/beneficialOwnershipOrControl",
        "/interests/interestLevel",
        "/interests/share",
        "/interests/share/exact",
        "/interests/startDate",
        "/interests/type",
        "/name",
        "/names",
        "/names/familyName",
        "/names/fullName",
        "/names/givenName",
        "/names/type",
        "/nationalities",
        "/nationalities/code",
        "/personType",
        "/statementDate",
        "/statementID",
        "/statementType",
        "/subject",
        "/subject/describedByEntityStatement",
    ]


def test_get_additional_fields_info():

    simple_data = {
        "non_additional_field": "a",
        "non_additional_list": [1, 2],
        "non_additional_object": {"z": "z"},
        "additional_object": {"a": "a", "b": "b"},
        "additional_list": [
            {"c": "c", "d": "d"},
            {"e": "e", "f": "f"},
            {"e": "e", "f": "f"},
        ],
    }

    schema_fields = {
        "/non_additional_field",
        "/non_additional_list",
        "/non_additional_object",
        "/non_additional_object/z",
    }

    additional_field_info = get_additional_fields_info(
        json_data=simple_data, schema_fields=schema_fields, context={}
    )
    assert len(additional_field_info) == 8
    assert sum(info["count"] for info in additional_field_info.values()) == 10
    assert (
        len(
            [
                info
                for info in additional_field_info.values()
                if info["root_additional_field"]
            ]
        )
        == 2
    )


@freeze_time("2020-01-02")
def test_get_orgids_prefixes_live(requests_mock):
    file_contents = mock.mock_open(
        read_data='{"downloaded": "2020-01-01", "lists": [{"code": "001"}, {"code": "002"}]}'
    )
    text = {"lists": [{"code": str(i)} for i in range(150)]}
    requests_mock.get("http://org-id.guide/download.json", text=json.dumps(text))

    with mock.patch("builtins.open", file_contents):
        data = get_orgids_prefixes()
        assert len(data) == 150


class DummyReleaseSchemaObj:
    def __init__(self, schema_host):
        self.schema_host = schema_host
        self.config = None

    def get_pkg_schema_obj(self):
        with open(os.path.join(self.schema_host, "release-package-schema.json")) as fp:
            schema_json = json.load(fp)
        return schema_json


class DummyRecordSchemaObj:
    def __init__(self, schema_host):
        self.schema_host = schema_host
        self.config = None

    def get_pkg_schema_obj(self):
        with open(os.path.join(self.schema_host, "record-package-schema.json")) as fp:
            schema_json = json.load(fp)
        return schema_json


@pytest.mark.parametrize(
    "package_schema_filename,filename,schema_subdir,validation_error_jsons_expected",
    [
        ("release-package-schema.json", "releases_no_validation_errors.json", "", []),
        ("record-package-schema.json", "records_no_validation_errors.json", "", []),
        (
            "release-package-schema.json",
            "releases_non_unique.json",
            "",
            [
                {
                    "message": "Non-unique id values",
                    "validator": "uniqueItems",
                    "assumption": None,
                    "message_type": "uniqueItems",
                    "path_no_number": "releases",
                    "header": "releases",
                    "header_extra": "releases",
                    "null_clause": "",
                    "error_id": "uniqueItems_with_id",
                    "values": [
                        {"path": "releases", "value": "EXAMPLE-1-1"},
                        {"path": "releases", "value": "EXAMPLE-1-2"},
                    ],
                }
            ],
        ),
        (
            "release-package-schema.json",
            "releases_non_unique_no_id.json",
            "",
            [
                {
                    "message": "'id' is missing but required",
                    "validator": "required",
                    "assumption": None,
                    "message_type": "required",
                    "path_no_number": "releases",
                    "header": "id",
                    "header_extra": "releases/[number]",
                    "null_clause": "",
                    "error_id": None,
                    "values": [{"path": "releases/0"}, {"path": "releases/1"}],
                },
                {
                    "message": "Array has non-unique elements",
                    "validator": "uniqueItems",
                    "assumption": None,
                    "message_type": "uniqueItems",
                    "path_no_number": "releases",
                    "header": "releases",
                    "header_extra": "releases",
                    "null_clause": "",
                    "error_id": "uniqueItems_no_ids",
                    "values": [{"path": "releases"}],
                },
            ],
        ),
        (
            "record-package-schema.json",
            "records_non_unique_no_ocid.json",
            "",
            [
                {
                    "message": "'ocid' is missing but required",
                    "validator": "required",
                    "assumption": None,
                    "message_type": "required",
                    "path_no_number": "records",
                    "header": "ocid",
                    "header_extra": "records/[number]",
                    "null_clause": "",
                    "error_id": None,
                    "values": [{"path": "records/0"}, {"path": "records/1"}],
                },
                {
                    "message": "Array has non-unique elements",
                    "validator": "uniqueItems",
                    "assumption": None,
                    "message_type": "uniqueItems",
                    "path_no_number": "records",
                    "header": "records",
                    "header_extra": "records",
                    "null_clause": "",
                    "error_id": "uniqueItems_no_ids",
                    "values": [{"path": "records"}],
                },
            ],
        ),
        # Check that we handle unique arrays correctly also
        # (e.g. that we don't incorrectly claim they are not unique)
        (
            "release-package-schema.json",
            "releases_unique.json",
            "",
            [
                {
                    "message": "'id' is missing but required",
                    "validator": "required",
                    "assumption": None,
                    "message_type": "required",
                    "path_no_number": "releases",
                    "header": "id",
                    "header_extra": "releases/[number]",
                    "null_clause": "",
                    "error_id": None,
                    "values": [{"path": "releases/0"}, {"path": "releases/1"}],
                }
            ],
        ),
        (
            "record-package-schema.json",
            "records_unique.json",
            "",
            [
                {
                    "message": "'ocid' is missing but required",
                    "validator": "required",
                    "assumption": None,
                    "message_type": "required",
                    "path_no_number": "records",
                    "header": "ocid",
                    "header_extra": "records/[number]",
                    "null_clause": "",
                    "error_id": None,
                    "values": [{"path": "records/0"}, {"path": "records/1"}],
                }
            ],
        ),
    ],
)
def test_validation_release_or_record_package(
    package_schema_filename, filename, validation_error_jsons_expected, schema_subdir
):
    schema_host = os.path.join(
        os.path.dirname(os.path.realpath(__file__)),
        "fixtures",
        "common",
        schema_subdir,
        "",
    )
    with open(os.path.join(schema_host, filename)) as fp:
        json_data = json.load(fp)

    if isinstance(json_data, dict) and "records" in json_data:
        DummySchemaObj = DummyRecordSchemaObj
    else:
        DummySchemaObj = DummyReleaseSchemaObj

    validation_errors = get_schema_validation_errors(
        json_data,
        DummySchemaObj(schema_host),
        package_schema_filename,
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

    def strip_nones(list_of_dicts):
        out = []
        for a_dict in list_of_dicts:
            out.append(
                {key: value for key, value in a_dict.items() if value is not None}
            )
        return out

    assert strip_nones(validation_error_jsons) == strip_nones(
        validation_error_jsons_expected
    )


def test_dont_error_on_decimal_in_unique_validator_key():
    class DummySchemaObj:
        config = None
        schema_host = None

        def get_pkg_schema_obj(self):
            return {
                "type": ["array"],
                "minItems": 2,
            }

    validation_errors = get_schema_validation_errors(
        [Decimal("3.1")], DummySchemaObj(), "", {}, {}
    )
    assert len(validation_errors) == 1
    validation_error_json = list(validation_errors.keys())[0]
    assert "[3.1]" in validation_error_json
    assert "[Decimal('3.1')] is too short" in validation_error_json


def test_property_that_is_not_json_schema_doesnt_raise_exception(caplog, tmpdir):
    tmpdir.join("test.json").write(
        json.dumps({"properties": {"bad_property": "not_a_json_schema"}})
    )

    class DummySchemaObj:
        config = None
        schema_host = os.path.join(str(tmpdir), "")

        def get_pkg_schema_obj(self):
            return {"$ref": "test.json"}

    validation_errors = get_schema_validation_errors({}, DummySchemaObj(), "", {}, {})
    assert validation_errors == {}
    assert (
        "A 'properties' object contains a 'bad_property' value that is not a JSON Schema: 'not_a_json_schema'"
        in caplog.text
    )


@pytest.mark.parametrize(
    ("filedate", "checkdate", "result"),
    (
        ("2020-01-15", "2020-01-14", True),
        ("2020-01-15", "2020-01-16", False),
        ("2020-01-15", "2020-01-15", True),
        ("1998-01-01", "1999-01-01", False),
        ("1999-01-01", "1998-01-01", True),
        ("2000-01-01", "2020-01-01", False),
    ),
)
def test_org_id_file_fresh_dates(filedate, checkdate, result):
    """Check that the date in the file data is greater than or equal to check date."""
    assert (
        org_id_file_fresh(
            {"downloaded": filedate}, datetime.strptime(checkdate, "%Y-%m-%d").date()
        )
        is result
    )


@freeze_time("1955-11-12")
def test_get_orgids_prefixes_does_not_make_request_when_in_date_file_found(
    requests_mock,
):
    file_data = {
        "downloaded": "2020-01-01",
        "lists": [{"code": "001"}, {"code": "002"}],
    }

    with mock.patch("builtins.open", mock.mock_open(read_data=json.dumps(file_data))):
        get_orgids_prefixes()
        assert not requests_mock.called


@freeze_time("2020-01-02")
def test_get_orgids_prefixes_makes_request_when_file_out_of_date(requests_mock):
    file_data = {
        "downloaded": "2020-01-01",
        "lists": [{"code": "001"}, {"code": "002"}],
    }
    request_data = {"lists": [{"code": "001"}, {"code": "002"}]}

    requests_mock.get(
        "http://org-id.guide/download.json", text=json.dumps(request_data)
    )

    with mock.patch("builtins.open", mock.mock_open(read_data=json.dumps(file_data))):
        get_orgids_prefixes()
        assert requests_mock.called


@freeze_time("2020-01-02")
def test_get_orgids_prefixes_returns_file_ids_when_file_in_date(requests_mock):
    file_data = {
        "downloaded": "2020-01-02",
        "lists": [{"code": "file-id-1"}, {"code": "file-id-2"}],
    }

    requests_mock.get("http://org-id.guide/download.json")

    with mock.patch("builtins.open", mock.mock_open(read_data=json.dumps(file_data))):
        assert sorted(get_orgids_prefixes()) == ["file-id-1", "file-id-2"]


@freeze_time("2020-01-02")
def test_get_orgids_prefixes_returns_downloaded_ids_when_file_out_of_date(
    requests_mock,
):
    file_data = {
        "downloaded": "2020-01-01",
        "lists": [{"code": "file-id-1"}, {"code": "file-id-2"}],
    }
    request_data = {
        "lists": [{"code": "dl-id-001"}, {"code": "dl-id-002"}, {"code": "dl-id-003"}]
    }

    requests_mock.get(
        "http://org-id.guide/download.json", text=json.dumps(request_data)
    )

    with mock.patch("builtins.open", mock.mock_open(read_data=json.dumps(file_data))):
        assert sorted(get_orgids_prefixes()) == ["dl-id-001", "dl-id-002", "dl-id-003"]


@freeze_time("2020-01-02")
def test_get_orgids_prefixes_opens_file_once_when_in_date(requests_mock):
    file_data = {
        "downloaded": "2020-01-02",
        "lists": [{"code": "file-id-1"}, {"code": "file-id-2"}],
    }

    with mock.patch(
        "builtins.open", mock.mock_open(read_data=json.dumps(file_data))
    ) as file_mock:
        get_orgids_prefixes()
        assert file_mock.call_count == 1


@freeze_time("2020-01-02")
@mock.patch("libcove.lib.common.NamedTemporaryFile")
@mock.patch("libcove.lib.common.os.rename")
def test_get_orgids_prefixes_opens_and_moves_file_when_updating(
    rename_mock, tmp_mock, requests_mock
):
    tmp_mock.return_value.__enter__.return_value.name = "/path/to/tmp"
    file_data = {
        "downloaded": "2020-01-01",
        "lists": [{"code": "file-id-1"}, {"code": "file-id-2"}],
    }
    request_data = {
        "lists": [{"code": "dl-id-001"}, {"code": "dl-id-002"}, {"code": "dl-id-003"}]
    }

    requests_mock.get(
        "http://org-id.guide/download.json", text=json.dumps(request_data)
    )

    with mock.patch(
        "builtins.open", mock.mock_open(read_data=json.dumps(file_data))
    ) as file_mock:
        get_orgids_prefixes()
        assert file_mock.call_count == 1
        assert rename_mock.call_count == 1
        assert rename_mock.call_args_list[0][0][0] == "/path/to/tmp"
        assert rename_mock.call_args_list[0][0][1].endswith("org-ids.json")


def test_add_field_coverage():
    assert add_field_coverage({}, {}) == {}
    assert add_field_coverage({}, {"test": "not empty"}) == {}
    assert add_field_coverage({"properties": {}}, {}) == {"properties": {}}
    assert add_field_coverage({"properties": {"test": {}}}, {}) == {
        "properties": {"test": {"coverage": {"checks": 1}}}
    }
    assert add_field_coverage({"properties": {"test": {}}}, {"test": None}) == {
        "properties": {"test": {"coverage": {"checks": 1}}}
    }
    assert add_field_coverage({"properties": {"test": {}}}, {"test": []}) == {
        "properties": {"test": {"coverage": {"checks": 1}}}
    }
    assert add_field_coverage({"properties": {"test": {}}}, {"test": {}}) == {
        "properties": {"test": {"coverage": {"checks": 1}}}
    }
    assert add_field_coverage({"properties": {"test": {}}}, {"test": 0}) == {
        "properties": {"test": {"coverage": {"checks": 1}}}
    }
    assert add_field_coverage({"properties": {"test": {}}}, {"test": ""}) == {
        "properties": {"test": {"coverage": {"checks": 1}}}
    }
    assert add_field_coverage({"properties": {"test": {}}}, {"test": "not empty"}) == {
        "properties": {"test": {"coverage": {"successes": 1, "checks": 1}}}
    }

    assert add_field_coverage({"properties": {"parent": {"properties": {}}}}, {}) == {
        "properties": {"parent": {"coverage": {"checks": 1}, "properties": {}}}
    }
    assert add_field_coverage(
        {"properties": {"parent": {"properties": {"test": {}}}}}, {"parent": {}}
    ) == {
        "properties": {
            "parent": {
                "coverage": {"checks": 1},
                "properties": {"test": {"coverage": {"checks": 1}}},
            }
        }
    }
    assert add_field_coverage(
        {"properties": {"parent": {"properties": {"test": {}}}}},
        {"parent": {"test": {}}},
    ) == {
        "properties": {
            "parent": {
                "coverage": {
                    "successes": 1,
                    "checks": 1,
                },
                "properties": {"test": {"coverage": {"checks": 1}}},
            }
        }
    }
    assert add_field_coverage(
        {"properties": {"parent": {"properties": {"test": {}}}}},
        {"parent": {"test": "not empty"}},
    ) == {
        "properties": {
            "parent": {
                "coverage": {
                    "successes": 1,
                    "checks": 1,
                },
                "properties": {"test": {"coverage": {"successes": 1, "checks": 1}}},
            }
        }
    }
    assert add_field_coverage(
        {"properties": {"parent": {"properties": {"test": {}}}}},
        {
            "notinschema": {"notinschemachild": "not empty"},
            "parent": {"notinschemaeither": "not empty", "test": "not empty"},
        },
    ) == {
        "properties": {
            "parent": {
                "coverage": {
                    "successes": 1,
                    "checks": 1,
                },
                "properties": {"test": {"coverage": {"successes": 1, "checks": 1}}},
            }
        }
    }

    assert add_field_coverage({"items": {}}, []) == {"items": {}}
    assert add_field_coverage({"items": {"properties": {}}}, []) == {
        "items": {"properties": {}}
    }
    assert add_field_coverage({"items": {"properties": {"test": {}}}}, []) == {
        "items": {"properties": {"test": {}}}
    }
    assert add_field_coverage({"items": {"properties": {"test": {}}}}, [{}]) == {
        "items": {"properties": {"test": {"coverage": {"checks": 1}}}}
    }
    assert add_field_coverage(
        {"items": {"properties": {"test": {}}}}, [{"test": "not empty"}]
    ) == {
        "items": {"properties": {"test": {"coverage": {"successes": 1, "checks": 1}}}}
    }
    assert add_field_coverage(
        {"items": {"properties": {"test": {}}}}, [{"test": "not empty"}, {}, {}]
    ) == {
        "items": {"properties": {"test": {"coverage": {"successes": 1, "checks": 3}}}}
    }

    assert add_field_coverage(
        {
            "items": {
                "properties": {
                    "parent": {"items": {"properties": {"child1": {}, "child2": {}}}}
                }
            }
        },
        [{}, {"parent": []}, {"parent": [{}]}, {"parent": [{"child1": "not empty"}]}],
    ) == {
        "items": {
            "properties": {
                "parent": {
                    "coverage": {
                        "successes": 2,
                        "checks": 4,
                    },
                    "items": {
                        "properties": {
                            "child1": {"coverage": {"successes": 1, "checks": 2}},
                            "child2": {"coverage": {"checks": 2}},
                        }
                    },
                }
            }
        }
    }


def test_add_field_coverage_percentages():
    assert add_field_coverage_percentages({}) == {}
    assert add_field_coverage_percentages({"properties": {}}) == {"properties": {}}
    assert add_field_coverage_percentages({"properties": {"test": {}}}) == {
        "properties": {
            "test": {"coverage": {"successes": 0, "checks": 0, "percentage": 0}}
        }
    }
    assert add_field_coverage_percentages(
        {"properties": {"test": {"coverage": {"checks": 3}}}}
    ) == {
        "properties": {
            "test": {"coverage": {"successes": 0, "checks": 3, "percentage": 0}}
        }
    }
    assert add_field_coverage_percentages(
        {"properties": {"test": {"coverage": {"successes": 1, "checks": 3}}}}
    ) == {
        "properties": {
            "test": {"coverage": {"successes": 1, "checks": 3, "percentage": 33}}
        }
    }

    assert add_field_coverage_percentages({"properties": {"test": {}}}) == {
        "properties": {
            "test": {"coverage": {"successes": 0, "checks": 0, "percentage": 0}}
        }
    }
    assert add_field_coverage_percentages(
        {"properties": {"test": {"coverage": {"checks": 3}}}}
    ) == {
        "properties": {
            "test": {"coverage": {"successes": 0, "checks": 3, "percentage": 0}}
        }
    }
    assert add_field_coverage_percentages(
        {"properties": {"test": {"coverage": {"successes": 1, "checks": 3}}}}
    ) == {
        "properties": {
            "test": {"coverage": {"successes": 1, "checks": 3, "percentage": 33}}
        }
    }

    assert add_field_coverage_percentages(
        {"items": {"properties": {"test": {"coverage": {"successes": 1, "checks": 3}}}}}
    ) == {
        "items": {
            "properties": {
                "test": {"coverage": {"successes": 1, "checks": 3, "percentage": 33}}
            }
        }
    }


def schema_obj_from_str(schema_str):
    schema_obj = SchemaJsonMixin()
    schema_obj.schema_host = ""
    schema_obj.schema_str = schema_str
    return schema_obj


def test_get_field_coverage():
    assert get_field_coverage(schema_obj_from_str("{}"), []) == {}
    assert get_field_coverage(schema_obj_from_str("{}"), [{}]) == {}
    assert (
        get_field_coverage(
            schema_obj_from_str(
                """{
                    "properties": {
                        "test": {}
                    }
                }"""
            ),
            [{}],
        )
        == {
            "properties": {
                "test": {"coverage": {"checks": 1, "successes": 0, "percentage": 0}}
            }
        }
    )

    # Test that refs to the same object are counted separately
    assert (
        get_field_coverage(
            schema_obj_from_str(
                """{
                    "properties": {
                        "test1": {"$ref": "#/definitions/Test"},
                        "test2": {"$ref": "#/definitions/Test"}
                    },
                    "definitions": {
                        "Test": {
                            "properties": {"child": {}}
                        }
                    }
            }"""
            ),
            [{}, {"test1": {"child": "not empty"}}, {"test1": {}}],
        )["properties"]
        == {
            "test1": {
                "properties": {
                    "child": {
                        "coverage": {"checks": 2, "successes": 1, "percentage": 50}
                    }
                },
                "coverage": {
                    "checks": 3,
                    "successes": 1,
                    "percentage": 33,
                },
            },
            "test2": {
                "properties": {
                    "child": {
                        "coverage": {"checks": 0, "successes": 0, "percentage": 0}
                    }
                },
                "coverage": {
                    "checks": 3,
                    "successes": 0,
                    "percentage": 0,
                },
            },
        }
    )


def common_fixtures(filename):
    return os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "fixtures", "common", filename
    )


def test_get_field_coverage_oc4ids():
    # Compare the actual json output, to ensure order is the same
    assert (
        json.dumps(
            get_field_coverage(
                schema_obj_from_str(
                    open(common_fixtures("oc4ids_project-schema_0__9__2.json")).read()
                ),
                json.load(open(common_fixtures("oc4ids_example.json")))["projects"],
            ),
            indent=2,
        )
        == open(common_fixtures("oc4ids_example_coverage.json")).read()
    )


@pytest.mark.parametrize(
    ("data", "count", "errors"),
    (
        # Good cat
        ({"pet": "cat", "purry": "Very"}, 0, []),
        # Good dog
        ({"pet": "dog", "waggy": "Very"}, 0, []),
        # A cat with a wrong required field
        (
            {"pet": "cat", "waggy": "Yes!"},
            1,
            [{"message": "'purry' is missing but required"}],
        ),
        # A dog with a wrong required field
        (
            {"pet": "dog", "purry": "Yes!"},
            1,
            [{"message": "'waggy' is missing but required"}],
        ),
    ),
)
def test_oneOfEnumSelectorField(data, count, errors):

    with open(common_fixtures("schema_with_one_of_enum_selector_field.json")) as fp:
        schema = json.load(fp)

    class DummySchemaObj:
        config = None
        schema_host = None

        def get_pkg_schema_obj(self):
            return schema

    validation_errors = get_schema_validation_errors(data, DummySchemaObj(), "", {}, {})

    assert count == len(validation_errors)

    for i in range(0, len(errors)):
        validation_error_json = json.loads(list(validation_errors.keys())[i])
        assert validation_error_json["message"] == errors[i]["message"]


@pytest.mark.parametrize(
    ("data", "count", "errors"),
    (
        # Good cat
        ([{"statementType": "animal", "pet": "cat", "purry": "Very"}], 0, []),
        # Good dog
        ([{"statementType": "animal", "pet": "dog", "waggy": "Very"}], 0, []),
        # A cat with a wrong required field
        (
            [{"statementType": "animal", "pet": "cat", "waggy": "Yes!"}],
            1,
            [{"message": "'purry' is missing but required"}],
        ),
        # A dog with a wrong required field
        (
            [{"statementType": "animal", "pet": "dog", "purry": "Yes!"}],
            1,
            [{"message": "'waggy' is missing but required"}],
        ),
        # A house
        ([{"statementType": "property"}], 0, []),
    ),
)
def test_one_of_enum_selector_field_inside_one_of_enum_selector_field(
    data, count, errors
):
    """This replicates how this will be used in BODS.
    It also tests that the 'statementType' key is checked by default."""

    with open(
        common_fixtures(
            "schema_with_one_of_enum_selector_field_inside_one_of_enum_selector_field.json"
        )
    ) as fp:
        schema = json.load(fp)

    class DummySchemaObj:
        config = None
        schema_host = None

        def get_pkg_schema_obj(self):
            return schema

    validation_errors = get_schema_validation_errors(data, DummySchemaObj(), "", {}, {})

    assert count == len(validation_errors)

    for i in range(0, len(errors)):
        validation_error_json = json.loads(list(validation_errors.keys())[i])
        assert validation_error_json["message"] == errors[i]["message"]


def test_get_additional_codelist_values():
    with open(
        os.path.join(
            os.path.dirname(os.path.realpath(__file__)),
            "fixtures",
            "common",
            "tenders_releases_2_releases_codelists.json",
        )
    ) as fp:
        json_data = json.load(fp)

    schema_obj = SchemaJsonMixin()
    schema_obj.schema_host = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), "fixtures", "common/"
    )
    schema_obj.release_pkg_schema_name = "release-package-schema.json"
    schema_obj.pkg_schema_url = os.path.join(
        schema_obj.schema_host, schema_obj.release_pkg_schema_name
    )
    schema_obj.codelists = "https://raw.githubusercontent.com/open-contracting/standard/1.1/schema/codelists/"

    additional_codelist_values = get_additional_codelist_values(schema_obj, json_data)
    assert additional_codelist_values == {
        ("releases/tag"): {
            "codelist": "releaseTag.csv",
            "codelist_url": "https://raw.githubusercontent.com/open-contracting/standard/1.1/schema/codelists/releaseTag.csv",
            "codelist_amend_urls": [],
            "field": "tag",
            "extension_codelist": False,
            "isopen": False,
            "path": "releases",
            "values": ["oh no"],
        },
        ("releases/tender/items/classification/scheme"): {
            "codelist": "itemClassificationScheme.csv",
            "codelist_url": "https://raw.githubusercontent.com/open-contracting/standard/1.1/schema/codelists/itemClassificationScheme.csv",
            "codelist_amend_urls": [],
            "extension_codelist": False,
            "field": "scheme",
            "isopen": True,
            "path": "releases/tender/items/classification",
            "values": ["GSINS"],
        },
        ("releases/aCodelistArray"): {
            "path": "releases",
            "field": "aCodelistArray",
            "codelist": "releaseTag.csv",
            "codelist_url": "https://raw.githubusercontent.com/open-contracting/standard/1.1/schema/codelists/releaseTag.csv",
            "codelist_amend_urls": [],
            "isopen": False,
            "values": ["AAA"],
            "extension_codelist": False,
        },
    }
