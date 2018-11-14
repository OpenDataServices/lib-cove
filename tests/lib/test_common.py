import json
import os
from collections import OrderedDict
from libcove.lib.common import SchemaJsonMixin, \
    get_json_data_generic_paths, get_json_data_deprecated_fields, get_fields_present, \
    _get_schema_deprecated_paths


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
