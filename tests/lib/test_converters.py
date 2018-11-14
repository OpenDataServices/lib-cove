import tempfile
import os
import json
from libcove.lib.converters import convert_json
from libcove.config import LibCoveConfig


def test_convert_json_1():

    cove_temp_folder = tempfile.mkdtemp(prefix='lib-cove-ocds-tests-', dir=tempfile.gettempdir())
    json_filename = os.path.join(os.path.dirname(
        os.path.realpath(__file__)), 'fixtures', 'converters', 'convert_json_1.json'
    )

    lib_cove_config = LibCoveConfig()
    print(cove_temp_folder)
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
