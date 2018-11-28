LIB_COVE_CONFIG_DEFAULT = {
    'flatten_tool': {
        'disable_local_refs': True,
        'remove_empty_schema_columns': True,
    },
    'root_list_path': 'main',
    'root_id': 'main',
    'root_is_list': False,
    'id_name': 'id',
    'convert_titles': False,
    'xml_comment': None,
}


class LibCoveConfig:
    def __init__(self, config=LIB_COVE_CONFIG_DEFAULT):
        self.config = config
