import pytest
import os
from libcove.lib.tools import get_file_type, ignore_errors
from libcove.lib.exceptions import UnrecognisedFileType


@pytest.mark.parametrize('file_name', ['basic.xlsx', 'basic.XLSX'])
def test_get_file_type_xlsx_string(file_name):
    assert get_file_type(file_name) == 'xlsx'


@pytest.mark.parametrize('file_name', ['test.csv', 'test.CSV'])
def test_get_file_type_csv_string(file_name):
    assert get_file_type(file_name) == 'csv'


@pytest.mark.parametrize('file_name', ['test.json', 'test.JSON'])
def test_get_file_type_json_string(file_name):
    assert get_file_type(file_name) == 'json'


def test_get_file_type_json_noextension_string():
    file_name = os.path.join(
        os.path.dirname(os.path.realpath(__file__)), 'fixtures', 'tools', 'test'
    )
    assert get_file_type(file_name) == 'json'


def test_get_file_unrecognised_file_type_string():
    with pytest.raises(UnrecognisedFileType):
        get_file_type('test')


def test_ignore_errors():
    """ Test the ignore_errors function """

    # Test data that would in real usage come from having parsed a json
    # document
    test_data = {
        'A': [
            {'B': 'C'},
            {'F': 'G'},
        ],
        'E': object(),
    }

    class obj_with_attr(object):
        test = None

    @ignore_errors
    def check_data(json_data):
        # KeyError
        json_data['B']
        # IndexError
        json_data['A'][2]
        # TypeError
        json_data['A'][0]['B'] + 2
        # AttributeError
        json_data['E'].test
        # ValueError
        int(json_data['A'][1]['F'])

    # Should pass without any exceptions
    check_data(test_data, ignore_errors=True)

    # Work our way down "correcting" the errors so we can
    # Check each exception is captured as expected
    try:
        check_data(test_data, ignore_errors=False)
    except KeyError:
        pass

    try:
        test_data['B'] = "exist"
        check_data(test_data, ignore_errors=False)
    except IndexError:
        pass

    try:
        test_data['A'].append({})
        check_data(test_data, ignore_errors=False)
    except TypeError:
        pass

    try:
        test_data['A'][0]['B'] = 1
        check_data(test_data, ignore_errors=False)
    except AttributeError:
        pass

    try:
        test_data['E'] = obj_with_attr()
        check_data(test_data, ignore_errors=False)
    except ValueError as e:
        print("Got %s " % e)
        return

    # Should not be reached!
    assert False, "All errors weren't tested"
