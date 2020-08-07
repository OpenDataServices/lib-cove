import collections
import csv
import datetime
import fcntl
import functools
import json
import os
import re
from collections import OrderedDict
from urllib.parse import urljoin, urlparse

import jsonref
import jsonschema.validators
import requests
from cached_property import cached_property
from django.utils.html import conditional_escape, escape, format_html
from flattentool import unflatten
from flattentool.schema import get_property_type_set
from jsonschema import FormatChecker, RefResolver
from jsonschema._utils import uniq
from jsonschema.exceptions import ValidationError

from .exceptions import cove_spreadsheet_conversion_error
from .tools import decimal_default, get_request

# Because we will be changing items on this validator, it's important we take a copy!
# Otherwise we could cause conflicts with other software in the same process.
validator = jsonschema.validators.extend(
    jsonschema.validators.Draft4Validator, validators={}
)

uniqueItemsValidator = validator.VALIDATORS.pop("uniqueItems")
LANGUAGE_RE = re.compile(
    "^(.*_(((([A-Za-z]{2,3}(-([A-Za-z]{3}(-[A-Za-z]{3}){0,2}))?)|[A-Za-z]{4}|[A-Za-z]{5,8})(-([A-Za-z]{4}))?(-([A-Za-z]{2}|[0-9]{3}))?(-([A-Za-z0-9]{5,8}|[0-9][A-Za-z0-9]{3}))*(-([0-9A-WY-Za-wy-z](-[A-Za-z0-9]{2,8})+))*(-(x(-[A-Za-z0-9]{1,8})+))?)|(x(-[A-Za-z0-9]{1,8})+)))$"
)
validation_error_template_lookup = {
    "date-time": "Date is not in the correct format",
    "uri": "Invalid 'uri' found",
    "string": "{}'{}' is not a string. Check that the value {} has quotes at the start and end. Escape any quotes in the value with '\\'",
    "integer": "{}'{}' is not a integer. Check that the value {} doesn’t contain decimal points or any characters other than 0-9. Integer values should not be in quotes. ",
    "number": "{}'{}' is not a number. Check that the value {} doesn’t contain any characters other than 0-9 and dot ('.'). Number values should not be in quotes. ",
    "object": "{}'{}' is not a JSON object",
    "array": "{}'{}' is not a JSON array",
}
# These are "safe" html that we trust
# Don't insert any values into these strings without ensuring escaping
# e.g. using django's format_html function.
validation_error_template_lookup_safe = {
    "date-time": "Date is not in the correct format",
    "uri": "Invalid 'uri' found",
    "string": "{}<code>{}</code> is not a string. Check that the value {} has quotes at the start and end. Escape any quotes in the value with <code>\</code>",
    "integer": "{}<code>{}</code> is not a integer. Check that the value {} doesn’t contain decimal points or any characters other than 0-9. Integer values should not be in quotes. ",
    "number": "{}<code>{}</code> is not a number. Check that the value {} doesn’t contain any characters other than 0-9 and dot (<code>.</code>). Number values should not be in quotes. ",
    "object": "{}<code>{}</code> is not a JSON object",
    "array": "{}<code>{}</code> is not a JSON array",
}


def unique_ids(validator, ui, instance, schema, id_name="id"):
    if ui and validator.is_type(instance, "array"):
        non_unique_ids = set()
        all_ids = set()
        for item in instance:
            try:
                item_id = item.get(id_name)
            except AttributeError:
                # if item is not a dict
                item_id = None
            if (
                item_id
                and not isinstance(item_id, list)
                and not isinstance(item_id, dict)
            ):
                if item_id in all_ids:
                    non_unique_ids.add(item_id)
                all_ids.add(item_id)
            else:
                if not uniq(instance):
                    msg = "Array has non-unique elements"
                    err = ValidationError(msg, instance=instance)
                    err.error_id = "uniqueItems_no_ids"
                    yield err
                    return

        for non_unique_id in sorted(non_unique_ids):
            msg = "Non-unique {} values".format(id_name)
            err = ValidationError(msg, instance=non_unique_id)
            err.error_id = "uniqueItems_with_{}".format(id_name)
            yield err


def required_draft4(validator, required, instance, schema):
    """
    required validator from
    https://github.com/Julian/jsonschema/blob/7a2cc2faf04a1182d3901bd907e87a746671f879/jsonschema/_validators.py#L291-L296

    Modified to return a validation message that is just the missing property, so that we can process that later.

    """
    if not validator.is_type(instance, "object"):
        return
    for property in required:
        if property not in instance:
            yield ValidationError(property)


def oneOf_draft4(validator, oneOf, instance, schema):
    """
    oneOf_draft4 validator from
    https://github.com/Julian/jsonschema/blob/d16713a4296663f3d62c50b9f9a2893cb380b7af/jsonschema/_validators.py#L337

    Modified to:
    - sort the instance JSON, so we get a reproducible output that we
      can can test more easily
    - If `statementType` is available, use that pick the correct
      sub-schema, and to yield those ValidationErrors. (Only
      applicable for BODS).
    """
    subschemas = enumerate(oneOf)
    all_errors = []
    validStatementTypes = []
    for index, subschema in subschemas:
        errs = list(validator.descend(instance, subschema, schema_path=index))
        if not errs:
            first_valid = subschema
            break
        properties = subschema.get("properties", {})
        if "statementType" in properties:
            if "statementType" in instance:
                try:
                    validStatementType = properties["statementType"].get("enum", [])[0]
                except IndexError:
                    continue
                if instance["statementType"] == validStatementType:
                    for err in errs:
                        yield err
                    return
                else:
                    validStatementTypes.append(validStatementType)
            else:
                yield ValidationError("statementType", validator="required")
                break
        all_errors.extend(errs)
    else:
        if validStatementTypes:
            yield ValidationError(
                "Invalid code found in statementType",
                instance=instance["statementType"],
                path=("statementType",),
                validator="enum",
            )
        else:
            yield ValidationError(
                "%s is not valid under any of the given schemas"
                % (json.dumps(instance, sort_keys=True, default=decimal_default),),
                context=all_errors,
            )

    more_valid = [s for i, s in subschemas if validator.is_valid(instance, s)]
    if more_valid:
        more_valid.append(first_valid)
        reprs = ", ".join(repr(schema) for schema in more_valid)
        yield ValidationError("%r is valid under each of %s" % (instance, reprs))


validator.VALIDATORS.pop("patternProperties")
validator.VALIDATORS["uniqueItems"] = unique_ids
validator.VALIDATORS["required"] = required_draft4
validator.VALIDATORS["oneOf"] = oneOf_draft4


# Properties this class might look for
# * cache_schema, boolean. This is deprecated, use the 'cache_all_requests' option in config instead
# * config, an instance of a config class.
class SchemaJsonMixin:
    @cached_property
    def schema_str(self):
        response = get_request(
            self.schema_url,
            config=getattr(self, "config", None),
            force_cache=getattr(self, "cache_schema", False),
        )
        return response.text

    @cached_property
    def pkg_schema_str(self):
        uri_scheme = urlparse(self.pkg_schema_url).scheme
        if uri_scheme == "http" or uri_scheme == "https":
            response = get_request(
                self.pkg_schema_url,
                config=getattr(self, "config", None),
                force_cache=getattr(self, "cache_schema", False),
            )
            return response.text
        else:
            with open(self.pkg_schema_url) as fp:
                return fp.read()

    @property
    def _schema_obj(self):
        return json.loads(self.schema_str, object_pairs_hook=OrderedDict)

    @property
    def _pkg_schema_obj(self):
        return json.loads(self.pkg_schema_str)

    def deref_schema(self, schema_str):
        try:
            return _deref_schema(schema_str, self.schema_host)
        except jsonref.JsonRefError as e:
            self.json_deref_error = e.message
            return {}

    def get_schema_obj(self, deref=False):
        if deref:
            return self.deref_schema(self.schema_str)
        return self._schema_obj

    def get_pkg_schema_obj(self, deref=False):
        if deref:
            return self.deref_schema(self.pkg_schema_str)
        return self._pkg_schema_obj

    def get_pkg_schema_fields(self):
        return set(schema_dict_fields_generator(self.get_pkg_schema_obj(deref=True)))


def schema_dict_fields_generator(schema_dict):
    if "properties" in schema_dict and isinstance(schema_dict["properties"], dict):
        for property_name, value in schema_dict["properties"].items():
            if "oneOf" in value:
                property_schema_dicts = value["oneOf"]
            else:
                property_schema_dicts = [value]
            for property_schema_dict in property_schema_dicts:
                if not isinstance(property_schema_dict, dict):
                    continue
                property_type_set = get_property_type_set(property_schema_dict)
                if "object" in property_type_set:
                    for field in schema_dict_fields_generator(property_schema_dict):
                        yield "/" + property_name + field
                elif "array" in property_type_set:
                    fields = schema_dict_fields_generator(
                        property_schema_dict.get("items", {})
                    )
                    for field in fields:
                        yield "/" + property_name + field
                yield "/" + property_name
    if "items" in schema_dict and isinstance(schema_dict["items"], dict):
        if "oneOf" in schema_dict["items"] and isinstance(
            schema_dict["items"]["oneOf"], list
        ):
            for oneOf in schema_dict["items"]["oneOf"]:
                for field in schema_dict_fields_generator(oneOf):
                    yield field


def get_schema_codelist_paths(
    schema_obj, obj=None, current_path=(), codelist_paths=None, use_extensions=False
):
    """Get a dict of codelist paths including the filename and if they are open.

    codelist paths are given as tuples of tuples:
        {("path", "to", "codelist"): (filename, open?), ..}
    """
    if codelist_paths is None:
        codelist_paths = {}

    if schema_obj:
        obj = schema_obj.get_pkg_schema_obj(deref=True, use_extensions=use_extensions)

    properties = obj.get("properties", {})
    if not isinstance(properties, dict):
        return codelist_paths
    for prop, value in properties.items():
        if current_path:
            path = current_path + (prop,)
        else:
            path = (prop,)

        if "codelist" in value and path not in codelist_paths:
            codelist_paths[path] = (value["codelist"], value.get("openCodelist", False))

        if value.get("type") == "object":
            get_schema_codelist_paths(None, value, path, codelist_paths)
        elif value.get("type") == "array" and value.get("items", {}).get("properties"):
            get_schema_codelist_paths(None, value["items"], path, codelist_paths)

    return codelist_paths


def load_codelist(url, config=None):
    codelist_map = {}

    response = get_request(url, config=config)
    response.raise_for_status()
    reader = csv.DictReader(line.decode("utf8") for line in response.iter_lines())
    for record in reader:
        code = record.get("Code") or record.get("code")
        title = record.get("Title") or record.get("Title_en")
        if not code:
            return {}
        codelist_map[code] = title

    return codelist_map


@functools.lru_cache()
def load_core_codelists(codelist_url, unique_files, config=None):
    codelists = {}
    for codelist_file in unique_files:
        try:
            codelist_map = load_codelist(codelist_url + codelist_file, config=config)
        except requests.exceptions.RequestException:
            return {}
        codelists[codelist_file] = codelist_map
    return codelists


@functools.lru_cache()
def _deref_schema(schema_str, schema_host):
    loader = CustomJsonrefLoader(schema_url=schema_host)
    deref_obj = jsonref.loads(schema_str, loader=loader, object_pairs_hook=OrderedDict)
    # Force evaluation of jsonref.loads here
    repr(deref_obj)
    return deref_obj


class CustomJsonrefLoader(jsonref.JsonLoader):
    """This ref loader is only for use with the jsonref library
    and NOT jsonschema."""

    def __init__(self, schema_url, **kwargs):
        self.schema_url = schema_url
        super().__init__(**kwargs)

    def get_remote_json(self, uri, **kwargs):
        # ignore url in ref apart from last part
        uri_info = urlparse(uri)
        uri = urljoin(self.schema_url, os.path.basename(uri_info.path))
        if "http" in uri_info.scheme:
            return super().get_remote_json(uri, **kwargs)
        else:
            with open(uri) as schema_file:
                return json.load(schema_file, **kwargs)


def common_checks_context(
    upload_dir,
    json_data,
    schema_obj,
    schema_name,
    context,
    extra_checkers=None,
    fields_regex=False,
    api=False,
    cache=True,
):
    schema_version = getattr(schema_obj, "version", None)
    schema_version_choices = getattr(schema_obj, "version_choices", None)

    if schema_version:
        schema_version_display_choices = tuple(
            (version, display_url[0])
            for version, display_url in schema_version_choices.items()
        )
        context["version_used"] = schema_version
        if not api:
            context.update(
                {
                    "version_display_choices": schema_version_display_choices,
                    "version_used_display": schema_version_choices[schema_version][0],
                }
            )

    schema_fields = schema_obj.get_pkg_schema_fields()

    additional_fields_all = get_additional_fields_info(
        json_data, schema_fields, context, fields_regex=fields_regex
    )

    additional_fields = sorted(
        get_counts_additional_fields(
            json_data,
            schema_obj,
            schema_name,
            context,
            fields_regex=fields_regex,
            additional_fields_info=additional_fields_all,
        )
    )

    additional_fields_count = sum(item[2] for item in additional_fields)
    additional_fields_all = get_additional_fields_info(
        json_data, schema_fields, context, fields_regex=fields_regex
    )

    context.update(
        {
            "data_only": additional_fields,
            "additional_fields": additional_fields_all,
            "additional_fields_count": additional_fields_count,
        }
    )

    cell_source_map = {}
    heading_source_map = {}
    if context["file_type"] != "json":  # Assume it is csv or xlsx
        with open(
            os.path.join(upload_dir, "cell_source_map.json")
        ) as cell_source_map_fp:
            cell_source_map = json.load(cell_source_map_fp)

        with open(
            os.path.join(upload_dir, "heading_source_map.json")
        ) as heading_source_map_fp:
            heading_source_map = json.load(heading_source_map_fp)

    # IMPORTANT: If you change this filename, you must change it also in lib-cove-web
    # https://github.com/OpenDataServices/lib-cove-web/blob/master/cove/views.py#L38
    # Otherwsie people can upload a file with this name and inject HTML.
    validation_errors_path = os.path.join(upload_dir, "validation_errors-3.json")
    if os.path.exists(validation_errors_path):
        with open(validation_errors_path) as validation_error_fp:
            validation_errors = json.load(validation_error_fp)
    else:
        validation_errors = get_schema_validation_errors(
            json_data,
            schema_obj,
            schema_name,
            cell_source_map,
            heading_source_map,
            extra_checkers=extra_checkers,
        )
        if cache:
            with open(validation_errors_path, "w+") as validation_error_fp:
                json.dump(
                    validation_errors,
                    validation_error_fp,
                    sort_keys=True,
                    indent=2,
                    default=decimal_default,
                )

    extensions = None
    if getattr(schema_obj, "extensions", None):
        extensions = {
            "extensions": schema_obj.extensions,
            "invalid_extension": schema_obj.invalid_extension,
            "is_extended_schema": schema_obj.extended,
            "extended_schema_url": schema_obj.extended_schema_url,
        }

    context.update(
        {
            "schema_url": schema_obj.pkg_schema_url,
            "extensions": extensions,
            "validation_errors": sorted(validation_errors.items()),
            "validation_errors_count": sum(
                len(value) for value in validation_errors.values()
            ),
            "common_error_types": [],
        }
    )

    json_data_gen_paths = get_json_data_generic_paths(json_data)
    context["deprecated_fields"] = get_json_data_deprecated_fields(
        json_data_gen_paths, schema_obj
    )

    missing_ids = get_json_data_missing_ids(json_data_gen_paths, schema_obj)
    if missing_ids:
        context.update({"structure_warnings": {"missing_ids": missing_ids}})

    if not api:
        context["json_data"] = json_data

    return {"context": context, "cell_source_map": cell_source_map}


def get_additional_codelist_values(schema_obj, json_data):
    schema_obj.process_codelists()

    additional_codelist_values = {}
    for path, values in _generate_data_path(json_data):
        if not isinstance(values, list):
            values = [values]

        path_no_num = tuple(key for key in path if isinstance(key, str))

        if path_no_num not in schema_obj.extended_codelist_schema_paths:
            continue

        codelist, isopen = schema_obj.extended_codelist_schema_paths[path_no_num]

        codelist_values = schema_obj.extended_codelists.get(codelist)
        if not codelist_values:
            continue

        for value in values:
            if str(value) in codelist_values:
                continue

            path_string = "/".join(path_no_num)

            if path_string not in additional_codelist_values:

                codelist_url = schema_obj.codelists + codelist
                codelist_amend_urls = []
                if hasattr(schema_obj, "extended_codelist_urls"):

                    # Replace URL if this codelist is overridden by an extension.
                    # Last one to be applied wins.
                    if schema_obj.extended_codelist_urls.get(codelist):
                        codelist_url = schema_obj.extended_codelist_urls[codelist][-1]

                    codelistadd = "+" + codelist
                    codelistsub = "-" + codelist
                    for codelist_key in schema_obj.extended_codelist_urls.keys():
                        if codelist_key == codelistadd:
                            for amended_codelist in schema_obj.extended_codelist_urls[
                                codelist_key
                            ]:
                                codelist_amend_urls.append(("+", amended_codelist))
                        if codelist_key == codelistsub:
                            for amended_codelist in schema_obj.extended_codelist_urls[
                                codelist_key
                            ]:
                                codelist_amend_urls.append(("-", amended_codelist))

                additional_codelist_values[path_string] = {
                    "path": "/".join(path_no_num[:-1]),
                    "field": path_no_num[-1],
                    "codelist": codelist,
                    "codelist_url": codelist_url,
                    "codelist_amend_urls": codelist_amend_urls,
                    "isopen": isopen,
                    "values": set(),
                    "extension_codelist": codelist not in schema_obj.core_codelists,
                    # "location_values": []
                }

            additional_codelist_values["/".join(path_no_num)]["values"].add(str(value))
            # additional_codelist_values['/'.join(path_no_num)]['location_values'].append((path, value))

    for codelist_value in additional_codelist_values.values():
        codelist_value["values"] = sorted(list(codelist_value["values"]))
    return additional_codelist_values


def get_additional_fields_info(json_data, schema_fields, context, fields_regex=False):
    fields_present = get_fields_present_with_examples(json_data)

    additional_fields = collections.OrderedDict()
    root_additional_fields = set()

    for field, field_info in fields_present.items():

        if field in schema_fields:
            continue
        if fields_regex and LANGUAGE_RE.search(field.split("/")[-1]):
            continue

        for root_additional_field in root_additional_fields:
            if field.startswith(root_additional_field):
                field_info["root_additional_field"] = False
                additional_fields[root_additional_field][
                    "additional_field_descendance"
                ][field] = field_info
                break
        else:
            field_info["root_additional_field"] = True
            field_info["additional_field_descendance"] = collections.OrderedDict()
            root_additional_fields.add(field)

        field_info["path"] = "/".join(field.split("/")[:-1])
        field_info["field_name"] = field.split("/")[-1]
        additional_fields[field] = field_info

    return additional_fields


def get_counts_additional_fields(
    json_data,
    schema_obj,
    schema_name,
    context,
    fields_regex=False,
    additional_fields_info=None,
):

    if not additional_fields_info:
        schema_fields = schema_obj.get_pkg_schema_fields()
        additional_fields_info = get_additional_fields_info(
            json_data, schema_fields, context, fields_regex=False
        )

    return [
        (field_info["path"], field_info["field_name"], field_info["count"])
        for field, field_info in additional_fields_info.items()
        if field_info["root_additional_field"]
    ]


def get_schema_validation_errors(
    json_data,
    schema_obj,
    schema_name,
    cell_src_map,
    heading_src_map,
    extra_checkers=None,
):
    pkg_schema_obj = schema_obj.get_pkg_schema_obj()

    validation_errors = collections.defaultdict(list)
    format_checker = FormatChecker()
    if extra_checkers:
        format_checker.checkers.update(extra_checkers)

    if getattr(schema_obj, "extended", None):
        resolver = CustomRefResolver(
            "",
            pkg_schema_obj,
            schema_url=schema_obj.schema_host,
            schema_file=schema_obj.extended_schema_file,
            file_schema_name=schema_obj.schema_name,
        )
    else:
        resolver = CustomRefResolver(
            "", pkg_schema_obj, schema_url=schema_obj.schema_host
        )

    our_validator = validator(
        pkg_schema_obj, format_checker=format_checker, resolver=resolver
    )
    for e in our_validator.iter_errors(json_data):
        message_safe = None
        message = e.message
        path = "/".join(str(item) for item in e.path)
        path_no_number = "/".join(
            str(item) for item in e.path if not isinstance(item, int)
        )

        value = {"path": path}
        cell_reference = cell_src_map.get(path)

        if cell_reference:
            first_reference = cell_reference[0]
            if len(first_reference) == 4:
                (
                    value["sheet"],
                    value["col_alpha"],
                    value["row_number"],
                    value["header"],
                ) = first_reference
            if len(first_reference) == 2:
                value["sheet"], value["row_number"] = first_reference

        header = value.get("header")

        header_extra = None
        pre_header = ""

        if not header and len(e.path):
            header = e.path[-1]
            if isinstance(e.path[-1], int) and len(e.path) >= 2:
                # We're dealing with elements in an array of items at this point
                pre_header = "Array Element "
                header_extra = "{}/[number]".format(e.path[-2])

        null_clause = ""
        validator_type = e.validator
        if e.validator in ("format", "type"):
            validator_type = e.validator_value
            if isinstance(e.validator_value, list):
                validator_type = e.validator_value[0]
                if "null" not in e.validator_value:
                    null_clause = "is not null, and"
            else:
                null_clause = "is not null, and"

            message_template = validation_error_template_lookup.get(
                validator_type, message
            )
            message_safe_template = validation_error_template_lookup_safe.get(
                validator_type
            )

            if message_template:
                message = message_template.format(pre_header, header, null_clause)

            if message_safe_template:
                message_safe = format_html(
                    message_safe_template, pre_header, header, null_clause
                )

        if e.validator == "oneOf" and e.validator_value[0] == {"format": "date-time"}:
            # Give a nice date related error message for 360Giving date `oneOf`s.
            message = validation_error_template_lookup["date-time"]
            message_safe = format_html(
                validation_error_template_lookup_safe["date-time"]
            )
            validator_type = "date-time"

        if not isinstance(e.instance, (dict, list)):
            value["value"] = e.instance

        if e.validator == "required":
            field_name = e.message
            parent_name = None
            if len(e.path) > 2:
                if isinstance(e.path[-1], int):
                    parent_name = e.path[-2]
                else:
                    parent_name = e.path[-1]

            heading = heading_src_map.get(path_no_number + "/" + e.message)
            if heading:
                field_name = heading[0][1]
                value["header"] = heading[0][1]
            header = field_name
            if parent_name:
                message = "'{}' is missing but required within '{}'".format(
                    field_name, parent_name
                )
                message_safe = format_html(
                    "<code>{}</code> is missing but required within <code>{}</code>",
                    field_name,
                    parent_name,
                )
            else:
                message = "'{}' is missing but required".format(field_name)
                message_safe = format_html(
                    "<code>{}</code> is missing but required", field_name, parent_name
                )

        if e.validator == "enum":
            if "isCodelist" in e.schema:
                continue
            message = "Invalid code found in '{}'".format(header)
            message_safe = format_html("Invalid code found in <code>{}</code>", header)

        if e.validator == "pattern":
            message_safe = format_html(
                "<code>{}</code> does not match the regex <code>{}</code>",
                header,
                e.validator_value,
            )

        if e.validator == "minItems" and e.validator_value == 1:
            message_safe = format_html(
                "<code>{}</code> is too short. You must supply at least one value, or remove the item entirely (unless it’s required).",
                e.instance,
            )

        if e.validator == "minLength" and e.validator_value == 1:
            message_safe = format_html(
                '<code>"{}"</code> is too short. Strings must be at least one character. This error typically indicates a missing value.',
                e.instance,
            )

        if message_safe is None:
            message_safe = escape(message)

        if header_extra is None:
            header_extra = header

        unique_validator_key = OrderedDict(
            [
                ("message", message),
                ("message_safe", conditional_escape(message_safe)),
                ("validator", e.validator),
                ("assumption", e.assumption if hasattr(e, "assumption") else None),
                # Don't pass this value for 'enum' and 'required' validators,
                # because it is not needed, and it will mean less grouping, which
                # we don't want.
                (
                    "validator_value",
                    e.validator_value
                    if e.validator not in ["enum", "required"]
                    else None,
                ),
                ("message_type", validator_type),
                ("path_no_number", path_no_number),
                ("header", header),
                ("header_extra", header_extra),
                ("null_clause", null_clause),
                ("error_id", e.error_id if hasattr(e, "error_id") else None),
            ]
        )
        validation_errors[json.dumps(unique_validator_key)].append(value)
    return dict(validation_errors)


def get_json_data_generic_paths(json_data, path=(), generic_paths=None):
    """Transform json data into a dictionary with keys made of json paths.

    Key are json paths (as tuples). Values are dictionaries with keys including specific
    indexes (which are not including in the top level keys), eg:

    {'a': 'I am', 'b': ['a', 'list'], 'c': [{'ca': 'ca1'}, {'ca': 'ca2'}, {'cb': 'cb'}]}

    will return:

    generic_paths = {
        ('a',): {('a',): 'I am'},
        ('b',): {
            ('b',): ['a', 'list'],
            ('b', 0): 'a',
            ('b', 1): 'list'
        },
        ('c',): {
            ('c',): [
                {'ca': 'ca1'},
                {'ca': 'ca2'},
                {'cb': 'cb'}
            ],
            ('c', 0): {'ca': 'ca1'},
            ('c', 1): {'ca': 'ca2'},
            ('c', 2): {'cb': 'cb'}
        },
        ('c', 'ca'): {
            ('c', 0, 'ca'): 'ca1',
            ('c', 1, 'ca'): 'ca2'
        },
        ('c', 'cb'): {('c', 2, 'cb'): 'cb'}
    }
    """
    if generic_paths is None:
        generic_paths = {}

    if isinstance(json_data, dict):
        iterable = list(json_data.items())
        if not iterable:
            generic_paths[path] = {}
    else:
        iterable = list(enumerate(json_data))
        if not iterable:
            generic_paths[path] = []

    for key, value in iterable:
        generic_key = tuple(i for i in path + (key,) if type(i) != int)

        if generic_paths.get(generic_key):
            generic_paths[generic_key][path + (key,)] = value
        else:
            generic_paths[generic_key] = {path + (key,): value}

        if isinstance(value, (dict, list)):
            get_json_data_generic_paths(value, path + (key,), generic_paths)

    return generic_paths


def get_json_data_deprecated_fields(json_data_paths, schema_obj):
    deprecated_schema_paths = _get_schema_deprecated_paths(schema_obj)
    deprecated_json_data_paths = [
        path for path in deprecated_schema_paths if path[0] in json_data_paths
    ]
    # Generate an OrderedDict sorted by deprecated field names (keys) mapping
    # to a unordered tuple of tuples:
    # {deprecated_field: ((path, path... ), (version, description))}
    deprecated_fields = OrderedDict()
    for generic_path in sorted(deprecated_json_data_paths, key=lambda tup: tup[0][-1]):
        deprecated_fields[generic_path[0][-1]] = tuple()

        # Be defensive against invalid schema data and corner cases.
        # e.g. (invalid OCDS data):
        # {"version":"1.1", "releases":{"buyer":{"additionalIdentifiers":[]}}}
        if hasattr(json_data_paths[generic_path[0]], "keys"):
            deprecated_fields[generic_path[0][-1]] += (
                tuple(key for key in json_data_paths[generic_path[0]].keys()),
                generic_path[1],
            )
        else:
            deprecated_fields[generic_path[0][-1]] += (
                (generic_path[0],),
                generic_path[1],
            )

    # Order the path tuples in values for deprecated_fields.
    deprecated_fields_output = OrderedDict()
    for field, paths in deprecated_fields.items():
        sorted_paths = tuple(sorted(paths[0]))

        # Avoid adding terminal paths for array indexes as only whole arrays can be deprecated.
        # TODO: check, is that true for all cases?
        slashed_paths = tuple(
            (
                "/".join((map(str, sort_path[:-1])))
                for sort_path in sorted_paths
                if type(sort_path[-1]) != int
            )
        )
        deprecated_fields_output[field] = {
            "paths": slashed_paths,
            "explanation": paths[1],
        }

    return deprecated_fields_output


def get_json_data_missing_ids(json_data_paths, schema_obj):
    non_required_schema_ids = _get_schema_non_required_ids(schema_obj)
    missing_ids_paths = []

    for generic_path in non_required_schema_ids:
        generic_no_id = generic_path[:-1]
        if generic_no_id in json_data_paths:
            for specific_path in json_data_paths[generic_no_id]:
                if type(specific_path[-1]) != int:
                    continue
                if not isinstance(json_data_paths[generic_no_id][specific_path], dict):
                    continue
                if "id" not in json_data_paths[generic_no_id][specific_path]:
                    missing_ids_paths.append(
                        "/".join(list(map(lambda i: str(i), specific_path)) + ["id"])
                    )

    return sorted(missing_ids_paths)


def _generate_data_path(json_data, path=()):
    if not json_data or not isinstance(json_data, dict):
        return path
    for key, value in json_data.items():
        if not value:
            continue
        if isinstance(value, list):
            if isinstance(value[0], dict):
                for num, item in enumerate(value):
                    yield from _generate_data_path(item, path + (key, num))
            else:
                yield path + (key,), value
        elif isinstance(value, dict):
            yield from _generate_data_path(value, path + (key,))
        else:
            yield path + (key,), value


def get_fields_present_with_examples(*args, **kwargs):
    counter = collections.OrderedDict()
    for key, value in fields_present_generator(*args, **kwargs):
        if key not in counter:
            counter[key] = {"count": 0, "examples": []}
        counter[key]["count"] += 1
        if len(counter[key]["examples"]) < 3:
            if not isinstance(value, (list, dict)):
                counter[key]["examples"].append(value)

    return counter


def get_fields_present(*args, **kwargs):
    return {
        key: value["count"]
        for key, value in get_fields_present_with_examples(*args, **kwargs).items()
    }


class CustomRefResolver(RefResolver):
    """This RefResolver is only for use with the jsonschema library"""

    def __init__(self, *args, **kw):
        # this is the name of the json file that you want replaced i.e release-schema.json
        self.file_schema_name = kw.pop("file_schema_name", "")
        # the path on the disk of the file you want to replace the ref
        self.schema_file = kw.pop("schema_file", None)
        # the url of the path to the schema. i.e https://standard.open-contracting.org/schema/1__1__1/
        # the name of the schema file is appended to this to make the full url.
        # this is ignored when you supply a file
        self.schema_url = kw.pop("schema_url", "")
        super().__init__(*args, **kw)

    def resolve_remote(self, uri):
        schema_name = uri.split("/")[-1]
        if self.schema_file and self.file_schema_name == schema_name:
            uri = self.schema_file
        else:
            uri = urljoin(self.schema_url, schema_name)

        document = self.store.get(uri)

        if document:
            return document
        if uri.startswith("http"):
            return super().resolve_remote(uri)
        else:
            with open(uri) as schema_file:
                result = json.load(schema_file)

        add_is_codelist(result)
        self.store[uri] = result
        return result


def _get_schema_deprecated_paths(
    schema_obj, obj=None, current_path=(), deprecated_paths=None
):
    """Get a list of deprecated paths and explanations for deprecation in a schema.

    Deprecated paths are given as tuples of tuples:
    ((path, to, field), (deprecation_version, description))
    """
    if deprecated_paths is None:
        deprecated_paths = []

    if schema_obj:
        obj = schema_obj.get_pkg_schema_obj(deref=True)

    properties = obj.get("properties", {})
    if not isinstance(properties, dict):
        return deprecated_paths
    for prop, value in properties.items():
        if current_path:
            path = current_path + (prop,)
        else:
            path = (prop,)

        if path not in deprecated_paths:
            if "deprecated" in value:
                deprecated_paths.append(
                    (
                        path,
                        (
                            value["deprecated"]["deprecatedVersion"],
                            value["deprecated"]["description"],
                        ),
                    )
                )
            elif (
                getattr(value, "__reference__", None)
                and "deprecated" in value.__reference__
            ):
                deprecated_paths.append(
                    (
                        path,
                        (
                            value.__reference__["deprecated"]["deprecatedVersion"],
                            value.__reference__["deprecated"]["description"],
                        ),
                    )
                )

        if value.get("type") == "object":
            _get_schema_deprecated_paths(None, value, path, deprecated_paths)
        elif value.get("type") == "array" and value.get("items", {}).get("properties"):
            _get_schema_deprecated_paths(None, value["items"], path, deprecated_paths)

    return deprecated_paths


def _get_schema_non_required_ids(
    schema_obj,
    obj=None,
    current_path=(),
    id_paths=None,
    array_parent=False,
    list_merge=False,
):
    """Get a list of paths for schema non-required object['id'] in arrays of objects.

    Return a list of tuples with generic paths (i.e. no indexes for array paths).
    Types "array" in json schema objects with property `"wholeListMerge": true` will
    be skipped.
    """
    if id_paths is None:
        id_paths = []
    if schema_obj:
        obj = schema_obj.get_pkg_schema_obj(deref=True)

    properties = obj.get("properties", {})
    no_required_id = "id" not in obj.get("required", [])

    if not isinstance(properties, dict):
        return id_paths
    for prop, value in properties.items():
        if current_path:
            path = current_path + (prop,)
        else:
            path = (prop,)

        if prop == "id" and no_required_id and array_parent and not list_merge:
            id_paths.append(path)

        if value.get("type") == "object":
            _get_schema_non_required_ids(None, value, path, id_paths)
        elif value.get("type") == "array" and value.get("items", {}).get("properties"):
            has_list_merge = "wholeListMerge" in value and value.get("wholeListMerge")
            _get_schema_non_required_ids(
                None,
                value["items"],
                path,
                id_paths,
                array_parent=True,
                list_merge=has_list_merge,
            )

    return id_paths


def fields_present_generator(json_data, prefix=""):
    if isinstance(json_data, dict):
        for key, value in json_data.items():
            if isinstance(value, list):
                yield prefix + "/" + key, value
                for item in value:
                    if isinstance(item, dict):
                        yield from fields_present_generator(item, prefix + "/" + key)
            elif isinstance(value, dict):
                yield prefix + "/" + key, value
                yield from fields_present_generator(value, prefix + "/" + key)
            else:
                yield prefix + "/" + key, value
    elif isinstance(json_data, list):
        for item in json_data:
            if isinstance(item, dict):
                yield from fields_present_generator(item, prefix)


def add_is_codelist(obj):
    """ This is needed so that we can detect enums that are arrays as the jsonschema library does not
    give you any parent information and the codelist property is on the parent in this case. Only applies to
    release.tag in core schema at the moment."""

    for prop, value in obj.get("properties", {}).items():
        if "codelist" in value:
            if "array" in value.get("type", ""):
                value["items"]["isCodelist"] = True
            else:
                value["isCodelist"] = True

        if value.get("type") == "object":
            add_is_codelist(value)
        elif value.get("type") == "array" and value.get("items", {}).get("properties"):
            add_is_codelist(value["items"])

    for value in obj.get("definitions", {}).values():
        if "properties" in value:
            add_is_codelist(value)


@cove_spreadsheet_conversion_error
def get_spreadsheet_meta_data(
    upload_dir, file_name, schema, file_type="xlsx", name="Meta"
):
    if file_type == "csv":
        input_name = upload_dir
    else:
        input_name = file_name
    output_name = os.path.join(upload_dir, "metatab.json")

    unflatten(
        input_name=input_name,
        output_name=output_name,
        input_format=file_type,
        metatab_only=True,
        metatab_schema=schema,
        metatab_name=name,
        metatab_vertical_orientation=True,
    )

    with open(output_name) as metatab_data:
        metatab_json = json.load(metatab_data)
    return metatab_json


def get_orgids_prefixes(orgids_url=None):
    """Get org-ids.json file from file system (or fetch upstream if it doesn't exist)

    A lock file is needed to avoid different processes trying to access the file
    trampling each other. If a process has the exclusive lock, a different process
    will wait until it is released.
    """
    local_org_ids_dir = os.path.dirname(os.path.realpath(__file__))
    local_org_ids_file = os.path.join(local_org_ids_dir, "org-ids.json")
    lock_file = os.path.join(local_org_ids_dir, "org-ids.json.lock")
    today = datetime.date.today()
    get_remote_file = False
    first_request = False

    if not orgids_url:
        orgids_url = "http://org-id.guide/download.json"

    if os.path.exists(local_org_ids_file):
        with open(lock_file, "w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            fp = open(local_org_ids_file)
            org_ids = json.load(fp)
            fp.close()
            fcntl.flock(lock, fcntl.LOCK_UN)
        date_str = org_ids.get("downloaded", "2000-1-1")
        date_downloaded = datetime.datetime.strptime(date_str, "%Y-%m-%d").date()
        if date_downloaded != today:
            get_remote_file = True
    else:
        get_remote_file = True
        first_request = True

    if get_remote_file:
        try:
            org_ids = requests.get(orgids_url).json()
            org_ids["downloaded"] = "%s" % today
            with open(lock_file, "w") as lock:
                fcntl.flock(lock, fcntl.LOCK_EX)
                fp = open(local_org_ids_file, "w")
                json.dump(org_ids, fp, indent=2)
                fp.close()
                fcntl.flock(lock, fcntl.LOCK_UN)
        except requests.exceptions.RequestException:
            if first_request:
                raise  # First time ever request fails
            pass  # Update fails

    return [org_list["code"] for org_list in org_ids["lists"]]
