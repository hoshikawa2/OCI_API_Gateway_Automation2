import base64
import json
import io
from fdk import response
import oci
import requests
import time
from openapi_schema_validator import validate
import os
import ast
from bravado_core.spec import Spec
from bravado_core.validate import validate_object
from datetime import datetime
from random import randrange

import Redaction

SENSITIVE_PATTERNS = [
    r"\d{3}-\d{2}-\d{4}",  # Social Security Number (SSN) pattern
    r"\d{4}[-\s]\d{4}[-\s]\d{4}[-\s]\d{4}",  # Credit card number pattern
    r"\(?\d{3}\)?[-\s.]?\d{3}[-\s.]?\d{4}",  # Phone number
    r"(0[1-9]|1[0-2])[-/.](0[1-9]|[12][0-9]|3[01])[-/.](19|20)\d\d",  # date of birth
    r"((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)",  # IP address
    r"[a-zA-Z0-9]{32}",  # API key
    r"^(\d{5}.\d{2}-\d)|(\d{8})$"
]

ATTRIBUTE_PATTERNS = [
    "documentNumber",
    "documentCustodyAgentAccountCode",
    "isinCode",
    "payingAgentAccountCode",
    "registrationParticipantAccountCode",
    "nome",
    "$ref",
    "cpf",
    "teste",
    "valor",
    "original",
    "type",
    "solicitacaoPagador",
    "expiracao",
    "chave",
    "description",
    "items",
    "required",
    "x-scope",
    "maxLength"
]

#### IDCS Routines
#### https://docs.oracle.com/en/learn/apigw-modeldeployment/index.html#introduction
#### https://docs.oracle.com/en/learn/migrate-api-to-api-gateway/#introduction

def auth_idcs(token, url, clientID, secretID):
    url = url + "/oauth2/v1/introspect"

    auth = clientID + ":" + secretID
    auth_bytes = auth.encode("ascii")
    auth_base64_bytes = base64.b64encode(auth_bytes)
    auth_base64_message = auth_base64_bytes.decode("ascii")

    headers = {
        'Content-Type': 'application/x-www-form-urlencoded',
        'Authorization': 'Basic ' + auth_base64_message
    }

    payload = "token=" + token

    response = requests.request("POST", url, headers=headers, data=payload)
    return response

def beautify_str(str_msg):
    msg = str(str_msg.encode('unicode_escape').decode("utf-8")).replace("\\n", " ")
    split_str = msg.split()
    return " ".join(split_str)

###

def replace_regex(variavel):
    variavel = variavel.replace("\\d", "[0-9]")
    variavel = variavel.replace("\\D", "[^0-9]")
    variavel = variavel.replace("\\.", "[.]")
    variavel = variavel.replace("\\w", "[a-zA-Z0-9_]")
    variavel = variavel.replace("\\W", "[^a-zA-Z0-9_]")
    variavel = variavel.replace("/^", "^")
    variavel = variavel.replace("$/", "$")

    return variavel

def remove_property(dictionary, property_name):
    keys_to_delete = [key for key in dictionary if key == property_name]
    for key in keys_to_delete:
        if ("\\s" in dictionary[key] or "\\S" in dictionary[key] or "\\w" in dictionary[key] or "\\W" in dictionary[key]
                or "\\b" in dictionary[key] or "\\B" in dictionary[key] or "\\A" in dictionary[key] or "\\Z" in dictionary[key]):
            del dictionary[key]
        else:
            dictionary[key] = replace_regex(dictionary[key])
    for value in dictionary.values():
        if isinstance(value, dict):
            remove_property(value, property_name)
        elif isinstance(value, list):
            for item in value:
                if isinstance(item, dict):
                    remove_property(item, property_name)
    return dictionary

def count_attributes(json_data):
    count = 0
    for key, value in json_data.items():
        count += 1
        if isinstance(value, dict):
            count += count_attributes(value)
    return count

def handler(ctx, data: io.BytesIO = None):
    config = oci.config.from_file("config")
    logging = oci.loggingingestion.LoggingClient(config)

    # functions context variables
    app_context = dict(ctx.Config())

    jsonData = ""

    try:
        header = json.loads(data.getvalue().decode('utf-8'))["data"]

        # IDCS Validation
        url = "https://idcs-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx.identity.oraclecloud.com"
        ClientId = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
        ClientSecret = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"

        # JSON Items counter
        jsonData = dict(json.loads(data.getvalue().decode('utf-8')).get("data"))["body"]
        jsonData = dict(json.loads(jsonData))
        c = count_attributes(jsonData)
        if (c > 21):
            rdata = json.dumps({
                "active": False,
                "context": {
                    "status_code": 401,
                    "message": "JSON exception",
                    "error": "JSON exception",
                }})

            return response.Response(
                ctx,
                status_code=401,
                response_data=rdata
            )

        try:
            body = dict(json.loads(data.getvalue().decode('utf-8')).get("data"))["body"]
            body = json.loads(body)
        except:
            body = None
        # body content
        body_schema_validation = None
        try:
            if (".apigatewayapi." not in header["body_schema_validation"]):
                body_schema_validation = ast.literal_eval(header["body_schema_validation"])
            else:
                body_schema_validation = header["body_schema_validation"]
        except:
            body_schema_validation = None

        # header values
        access_token = header["token"]

        authorization = auth_idcs(access_token, url, ClientId, ClientSecret)
        try:
            if (authorization.json().get("active") != True):
                return response.Response(
                    ctx,
                    status_code=401,
                    response_data=json.dumps({"active": False, "wwwAuthenticate": jsonData})
                )
        except(Exception) as ex1:
            jsonData = 'error parsing json payload: ' + str(ex1)
            put_logs_response = logging.put_logs(
                log_id="ocid1.log.oc1.iad.amaaaaaanamaaaaaanamaaaaaanamaaaaaanamaaaaaanamaaaaaan",
                put_logs_details=oci.loggingingestion.models.PutLogsDetails(
                    specversion="EXAMPLE-specversion-Value",
                    log_entry_batches=[
                        oci.loggingingestion.models.LogEntryBatch(
                            entries=[
                                oci.loggingingestion.models.LogEntry(
                                    data="error(a): " + jsonData,
                                    id="ocid1.test.oc1..00000001.EXAMPLE-id-Value")],
                            source="EXAMPLE-source-Value",
                            type="EXAMPLE-type-Value")]))
            rdata = json.dumps({
                "active": False,
                "context": {
                    "status_code": 401,
                    "message": "Unauthorized",
                    "body": body,
                    "body_schema_validation": json.dumps(body_schema_validation),
                    "error": str(ex1)
                }})

            return response.Response(
                ctx,
                status_code=401,
                response_data=rdata
            )

        rdata = json.dumps({
            "active": True,
            "context": {
                "body": body,
                "body_schema_validation": json.dumps(body_schema_validation)
            }})

        # Validate API spec
        if (body_schema_validation != None):
            if (".apigatewayapi." not in header["body_schema_validation"]):
                # Com validacao direto por propriedades (sem schemas e referencias)
                try:
                    validate(body, body_schema_validation["schema"])
                    return response.Response(
                        ctx, response_data=rdata,
                        status_code=200,
                        headers={"Content-Type": "application/json", "body": json.dumps(body)}
                    )
                except(Exception) as ex2:
                    error_msg = beautify_str(str(ex2))
                    redaction = Redaction.Redaction()
                    error_msg = redaction.redact(sensitive_pattern=SENSITIVE_PATTERNS, attribute_pattern=ATTRIBUTE_PATTERNS, message=error_msg)
                    put_logs_response = logging.put_logs(
                        log_id="ocid1.log.oc1.iad.amaaaaaanamaaaaaanamaaaaaanamaaaaaanamaaaaaanamaaaaaan",
                        put_logs_details=oci.loggingingestion.models.PutLogsDetails(
                            specversion="EXAMPLE-specversion-Value",
                            log_entry_batches=[
                                oci.loggingingestion.models.LogEntryBatch(
                                    entries=[
                                        oci.loggingingestion.models.LogEntry(
                                            data="error(b): " + error_msg,
                                            id="ocid1.test.oc1..00000001.EXAMPLE-id-Value")],
                                    source="EXAMPLE-source-Value",
                                    type="EXAMPLE-type-Value")]))
                    rdata = json.dumps({
                        "active": False,
                        "context": {
                            "status_code": 401,
                            "message": "Unauthorized",
                            "body": body,
                            "body_schema_validation": json.dumps(body_schema_validation),
                            "error": error_msg
                        }})

                    return response.Response(
                        ctx,
                        status_code=401,
                        response_data=rdata
                    )
            else:
                # Com schema de validação - Tanto swagger como Open API 3
                try:
                    bravado_config = {
                        'validate_swagger_spec': False,
                        'validate_requests': False,
                        'validate_responses': False,
                        'use_models': True,
                    }
                    contents = body_schema_validation.split(",")
                    apigateway_client = oci.apigateway.ApiGatewayClient(config)
                    api_spec = apigateway_client.get_api_content(contents[1])
                    spec_dict = json.loads(api_spec.data.content)
                    spec_dict = remove_property(spec_dict, "pattern")

                    spec = Spec.from_dict(spec_dict, config=bravado_config)
                    try:
                        schema = spec_dict["definitions"][contents[0]]
                    except:
                        schema = spec_dict["components"]["schemas"][contents[0]]

                    schema_without_pattern = remove_property(schema, "pattern")

                    validate_object(spec, schema_without_pattern, body)
                except (Exception) as ex3:
                    error_msg = beautify_str(str(ex3))
                    redaction = Redaction.Redaction()
                    error_msg = redaction.redact(sensitive_pattern=SENSITIVE_PATTERNS, attribute_pattern=ATTRIBUTE_PATTERNS, message=error_msg)
                    put_logs_response = logging.put_logs(
                        log_id="ocid1.log.oc1.iad.amaaaaaanamaaaaaanamaaaaaanamaaaaaanamaaaaaanamaaaaaan",
                        put_logs_details=oci.loggingingestion.models.PutLogsDetails(
                            specversion="EXAMPLE-specversion-Value",
                            log_entry_batches=[
                                oci.loggingingestion.models.LogEntryBatch(
                                    entries=[
                                        oci.loggingingestion.models.LogEntry(
                                            data="error(b): " + error_msg,
                                            id="ocid1.test.oc1..00000001.EXAMPLE-id-Value")],
                                    source="EXAMPLE-source-Value",
                                    type="EXAMPLE-type-Value")]))
                    rdata = json.dumps({
                        "active": False,
                        "context": {
                            "status_code": 401,
                            "message": "Unauthorized",
                            "body": body,
                            "body_schema_validation": json.dumps(body_schema_validation),
                            "error": error_msg
                        }})

                    return response.Response(
                        ctx,
                        status_code=401,
                        response_data=rdata
                    )

        return response.Response(
            ctx, response_data=rdata,
            status_code=200,
            headers={"Content-Type": "application/json", "body_schema_validation": body_schema_validation, "body": json.dumps(body)}
        )

    except(Exception) as ex:
        jsonData = 'error parsing json payload: ' + str(ex)
        put_logs_response = logging.put_logs(
            log_id="ocid1.log.oc1.iad.amaaaaaanamaaaaaanamaaaaaanamaaaaaanamaaaaaanamaaaaaan",
            put_logs_details=oci.loggingingestion.models.PutLogsDetails(
                specversion="EXAMPLE-specversion-Value",
                log_entry_batches=[
                    oci.loggingingestion.models.LogEntryBatch(
                        entries=[
                            oci.loggingingestion.models.LogEntry(
                                data="error(c): " + jsonData,
                                id="ocid1.test.oc1..00000001.EXAMPLE-id-Value")],
                        source="EXAMPLE-source-Value",
                        type="EXAMPLE-type-Value")]))

        pass

    return response.Response(
        ctx,
        status_code=401,
        response_data=json.dumps({"active": False, "wwwAuthenticate": jsonData})
    )
