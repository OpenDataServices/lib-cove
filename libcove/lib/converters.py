import json
import logging
import os
import shutil
import warnings

import flattentool
from flattentool.json_input import BadlyFormedJSONError

from .exceptions import cove_spreadsheet_conversion_error

logger = logging.getLogger(__name__)


def filter_conversion_warnings(conversion_warnings):
    out = []
    for w in conversion_warnings:
        if w.category is flattentool.exceptions.DataErrorWarning:
            out.append(str(w.message))
        else:
            logger.warning(w)
    return out


@cove_spreadsheet_conversion_error
def convert_spreadsheet(
    upload_dir,
    upload_url,
    file_name,
    file_type,
    lib_cove_config,
    schema_url=None,
    pkg_schema_url=None,
    metatab_name="Meta",
    replace=False,
    xml=False,
    xml_schemas=None,
    cache=True,
):
    context = {}
    if xml:
        output_file = "unflattened.xml"
        converted_path = os.path.join(upload_dir, "unflattened.xml")
    else:
        output_file = "unflattened.json"
        converted_path = os.path.join(upload_dir, "unflattened.json")
    cell_source_map_path = os.path.join(upload_dir, "cell_source_map.json")
    heading_source_map_path = os.path.join(upload_dir, "heading_source_map.json")
    encoding = "utf-8-sig"

    if file_type == "csv":
        # flatten-tool expects a directory full of CSVs with file names
        # matching what xlsx titles would be.
        # If only one upload file is specified, we rename it and move into
        # a new directory, such that it fits this pattern.
        input_name = os.path.join(upload_dir, "csv_dir")
        os.makedirs(input_name, exist_ok=True)
        destination = os.path.join(
            input_name, f"{lib_cove_config.config['root_list_path']}.csv"
        )
        shutil.copy(file_name, destination)
        try:
            with open(destination, encoding="utf-8-sig") as main_sheet_file:
                main_sheet_file.read()
        except UnicodeDecodeError:
            try:
                with open(destination, encoding="cp1252") as main_sheet_file:
                    main_sheet_file.read()
                encoding = "cp1252"
            except UnicodeDecodeError:
                encoding = "latin_1"
    else:
        input_name = file_name

    flattentool_options = {
        "output_name": converted_path,
        "input_format": file_type,
        "default_configuration": "RootListPath {}".format(
            lib_cove_config.config["root_list_path"]
        ),
        "encoding": encoding,
        "cell_source_map": cell_source_map_path,
        "heading_source_map": heading_source_map_path,
        "metatab_schema": pkg_schema_url,
        "metatab_name": metatab_name,
        "metatab_vertical_orientation": True,
        "disable_local_refs": lib_cove_config.config["flatten_tool"][
            "disable_local_refs"
        ],
    }

    if lib_cove_config.config.get("hashcomments"):
        flattentool_options["default_configuration"] += ",hashcomments"

    if xml:
        flattentool_options["xml"] = True
        flattentool_options["default_configuration"] += ",IDName {}".format(
            lib_cove_config.config.get("id_name", "id")
        )
        flattentool_options["xml_schemas"] = xml_schemas
        if lib_cove_config.config["flatten_tool"].get("xml_comment"):
            flattentool_options["xml_comment"] = lib_cove_config.config[
                "flatten_tool"
            ].get("xml_comment")

    else:
        flattentool_options.update(
            {
                "schema": schema_url,
                "convert_titles": True,
                "root_id": lib_cove_config.config["root_id"],
                "root_is_list": lib_cove_config.config.get("root_is_list", False),
                "id_name": lib_cove_config.config.get("id_name", None),
            }
        )

    conversion_warning_cache_path = os.path.join(
        upload_dir, "conversion_warning_messages.json"
    )
    if (
        not os.path.exists(converted_path)
        or not os.path.exists(cell_source_map_path)
        or replace
    ):
        with warnings.catch_warnings(record=True) as conversion_warnings:
            flattentool.unflatten(input_name, **flattentool_options)
            context["conversion_warning_messages"] = filter_conversion_warnings(
                conversion_warnings
            )

        if cache:
            with open(conversion_warning_cache_path, "w+") as fp:
                json.dump(context["conversion_warning_messages"], fp)

    elif os.path.exists(conversion_warning_cache_path):
        with open(conversion_warning_cache_path) as fp:
            context["conversion_warning_messages"] = json.load(fp)

    context["converted_file_size"] = os.path.getsize(converted_path)

    context.update(
        {
            "conversion": "unflatten",
            "converted_path": converted_path,
            "converted_url": "{}{}{}".format(
                upload_url, "" if upload_url.endswith("/") else "/", output_file
            ),
            "csv_encoding": encoding,
        }
    )
    return context


def convert_json(
    upload_dir,
    upload_url,
    file_name,
    lib_cove_config,
    root_list_path=None,
    root_id=None,
    schema_url=None,
    replace=False,
    request=None,
    flatten=False,
    cache=True,
    xml=False,
):
    context = {}
    converted_path = os.path.join(upload_dir, "flattened")

    if root_list_path is None:
        root_list_path = lib_cove_config.config["root_list_path"]

    if root_id is None:
        root_id = lib_cove_config.config["root_id"]

    flatten_kwargs = dict(
        output_name=converted_path,
        main_sheet_name=root_list_path,
        root_list_path=root_list_path,
        root_id=root_id,
        schema=schema_url,
        disable_local_refs=lib_cove_config.config["flatten_tool"]["disable_local_refs"],
        remove_empty_schema_columns=lib_cove_config.config["flatten_tool"][
            "remove_empty_schema_columns"
        ],
        root_is_list=lib_cove_config.config.get("root_is_list", False),
    )

    if xml:
        flatten_kwargs["xml"] = True
        flatten_kwargs["id_name"] = lib_cove_config.config.get("id_name", "id")

    try:
        conversion_warning_cache_path = os.path.join(
            upload_dir, "conversion_warning_messages.json"
        )
        conversion_exists = os.path.exists(f"{converted_path}.xlsx")
        if not conversion_exists or replace:
            with warnings.catch_warnings(record=True) as conversion_warnings:
                if flatten or (replace and conversion_exists):
                    flattentool.flatten(file_name, **flatten_kwargs)
                else:
                    return {"conversion": "flattenable"}
                context["conversion_warning_messages"] = filter_conversion_warnings(
                    conversion_warnings
                )

            if cache:
                with open(conversion_warning_cache_path, "w+") as fp:
                    json.dump(context["conversion_warning_messages"], fp)

        elif os.path.exists(conversion_warning_cache_path):
            with open(conversion_warning_cache_path) as fp:
                context["conversion_warning_messages"] = json.load(fp)

        context["converted_file_size"] = os.path.getsize(f"{converted_path}.xlsx")
        conversion_warning_cache_path_titles = os.path.join(
            upload_dir, "conversion_warning_messages_titles.json"
        )

        if lib_cove_config.config["convert_titles"]:
            with warnings.catch_warnings(record=True) as conversion_warnings_titles:
                flatten_kwargs.update(
                    dict(output_name=f"{converted_path}-titles", use_titles=True)
                )
                if not os.path.exists(f"{converted_path}-titles.xlsx") or replace:
                    flattentool.flatten(file_name, **flatten_kwargs)
                    context[
                        "conversion_warning_messages_titles"
                    ] = filter_conversion_warnings(conversion_warnings_titles)
                    with open(conversion_warning_cache_path_titles, "w+") as fp:
                        json.dump(context["conversion_warning_messages_titles"], fp)
                elif os.path.exists(conversion_warning_cache_path_titles):
                    with open(conversion_warning_cache_path_titles) as fp:
                        context["conversion_warning_messages_titles"] = json.load(fp)

            context["converted_file_size_titles"] = os.path.getsize(
                f"{converted_path}-titles.xlsx"
            )

    except BadlyFormedJSONError as err:
        raise err
    except Exception as err:
        logger.exception(err, extra={"request": request})
        return {"conversion": "flatten", "conversion_error": repr(err)}
    context.update(
        {
            "conversion": "flatten",
            "converted_path": converted_path,
            "converted_url": "{}{}flattened".format(
                upload_url, "" if upload_url.endswith("/") else "/"
            ),
        }
    )
    return context
