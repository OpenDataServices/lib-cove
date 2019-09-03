import tempfile
import os
import json
import csv
from libcove.lib.converters import convert_json, convert_spreadsheet
from libcove.config import LibCoveConfig


def test_convert_json_1():

    cove_temp_folder = tempfile.mkdtemp(prefix='lib-cove-ocds-tests-', dir=tempfile.gettempdir())
    json_filename = os.path.join(os.path.dirname(
        os.path.realpath(__file__)), 'fixtures', 'converters', 'convert_json_1.json'
    )

    lib_cove_config = LibCoveConfig()
    output = convert_json(cove_temp_folder, "", json_filename, lib_cove_config, flatten=True)

    assert output['converted_url'] == '/flattened'
    assert len(output['conversion_warning_messages']) == 0
    assert output['conversion'] == 'flatten'

    conversion_warning_messages_name = os.path.join(cove_temp_folder, "conversion_warning_messages.json")
    assert os.path.isfile(conversion_warning_messages_name)
    with open(conversion_warning_messages_name) as fp:
        conversion_warning_messages_data = json.load(fp)
    assert conversion_warning_messages_data == []

    assert os.path.isfile(os.path.join(cove_temp_folder, "flattened", "main.csv"))

    with open(os.path.join(cove_temp_folder, "flattened", "main.csv"), 'r') as csvfile:
        csvreader = csv.reader(csvfile)

        header = next(csvreader)
        assert header[0] == 'id'
        assert header[1] == 'title'

        row1 = next(csvreader)
        assert row1[0] == '1'
        assert row1[1] == 'Cat'

        row2 = next(csvreader)
        assert row2[0] == '2'
        assert row2[1] == 'Hat'


def test_convert_xml_1():

    cove_temp_folder = tempfile.mkdtemp(prefix='lib-cove-ocds-tests-', dir=tempfile.gettempdir())
    xml_filename = os.path.join(os.path.dirname(
        os.path.realpath(__file__)), 'fixtures', 'converters', 'convert_1.xml'
    )

    lib_cove_config = LibCoveConfig()
    output = convert_json(cove_temp_folder, "", xml_filename, lib_cove_config, flatten=True,
                          xml=True, root_list_path='iati-activity')

    assert output['converted_url'] == '/flattened'
    assert len(output['conversion_warning_messages']) == 0
    assert output['conversion'] == 'flatten'

    conversion_warning_messages_name = os.path.join(cove_temp_folder, "conversion_warning_messages.json")
    assert os.path.isfile(conversion_warning_messages_name)
    with open(conversion_warning_messages_name) as fp:
        conversion_warning_messages_data = json.load(fp)
    assert conversion_warning_messages_data == []

    assert os.path.isfile(os.path.join(cove_temp_folder, "flattened.xlsx"))
    assert os.path.isfile(os.path.join(cove_temp_folder, "flattened", "iati-activity.csv"))

    with open(os.path.join(cove_temp_folder, "flattened", "iati-activity.csv"), 'r') as csvfile:
        csvreader = csv.reader(csvfile)

        header = next(csvreader)
        assert header[0] == '@default-currency'
        assert header[1] == 'iati-identifier'

        row1 = next(csvreader)
        assert row1[0] == 'GBP'
        assert row1[1] == 'GB-TEST-13-example_ODSC_2019'


def test_convert_json_root_is_list_1():

    cove_temp_folder = tempfile.mkdtemp(prefix='lib-cove-ocds-tests-', dir=tempfile.gettempdir())
    json_filename = os.path.join(os.path.dirname(
        os.path.realpath(__file__)), 'fixtures', 'converters', 'convert_json_root_is_list_1.json'
    )

    lib_cove_config = LibCoveConfig()
    lib_cove_config.config['root_is_list'] = True
    output = convert_json(cove_temp_folder, "", json_filename, lib_cove_config, flatten=True)

    assert output['converted_url'] == '/flattened'
    assert len(output['conversion_warning_messages']) == 0
    assert output['conversion'] == 'flatten'

    conversion_warning_messages_name = os.path.join(cove_temp_folder, "conversion_warning_messages.json")
    assert os.path.isfile(conversion_warning_messages_name)
    with open(conversion_warning_messages_name) as fp:
        conversion_warning_messages_data = json.load(fp)
    assert conversion_warning_messages_data == []

    assert os.path.isfile(os.path.join(cove_temp_folder, "flattened", "main.csv"))

    with open(os.path.join(cove_temp_folder, "flattened", "main.csv"), 'r') as csvfile:
        csvreader = csv.reader(csvfile)

        header = next(csvreader)
        assert header[0] == 'id'
        assert header[1] == 'title'

        row1 = next(csvreader)
        assert row1[0] == '1'
        assert row1[1] == 'Cat'

        row2 = next(csvreader)
        assert row2[0] == '2'
        assert row2[1] == 'Hat'


def test_convert_csv_1():

    cove_temp_folder = tempfile.mkdtemp(prefix='lib-cove-ocds-tests-', dir=tempfile.gettempdir())
    csv_filename = os.path.join(os.path.dirname(
        os.path.realpath(__file__)), 'fixtures', 'converters', 'convert_csv_1.csv'
    )
    csv_schema_filename = os.path.join(os.path.dirname(
        os.path.realpath(__file__)), 'fixtures', 'converters', 'convert_csv_1_schema.json'
    )

    lib_cove_config = LibCoveConfig()
    lib_cove_config.config['id_name'] = 'thing_id'
    lib_cove_config.config['root_is_list'] = True

    output = convert_spreadsheet(cove_temp_folder, "", csv_filename, 'csv', lib_cove_config, schema_url=csv_schema_filename) # noqa

    assert output['conversion'] == 'unflatten'

    with open(output['converted_path']) as fp:
        json_data = json.load(fp)

    assert json_data == [
            {
                "thing_id": "1",
                "title": "Cat"
            },
            {
                "thing_id": "2",
                "title": "Hat"
            }
        ]
