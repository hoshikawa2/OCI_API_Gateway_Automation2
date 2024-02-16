import base64
import json
import io
from fdk import response
import oci
import requests
import yaml
import datetime

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

#Function used to load the configurations from the config.json file
def getOptions():
    fo = open("config.json", "r")
    config = fo.read()
    options = json.loads(config)
    return options

### OCI API Gateway Migration Routines

def migrate_to_apigw(payload, url, clientID, secretID):
    auth = clientID + ":" + secretID
    auth_bytes = auth.encode("ascii")
    auth_base64_bytes = base64.b64encode(auth_bytes)
    auth_base64_message = auth_base64_bytes.decode("ascii")

    headers = {
        'Content-Type': 'application/json',
        'Authorization': 'Basic ' + auth_base64_message
    }

    response = requests.request("POST", url, headers=headers, data=payload)
    return response

def find_base_path(strPath):
    base_path = strPath.split('/')[1]
    if (len(base_path) == 0):
        base_path = strPath
    else:
        base_path = "/" + base_path
    return base_path

def find_path(strPath):
    base_path = strPath.split('/')
    if (len(base_path) == 0):
        return strPath
    else:
        auxPath = ""
        skipCount = 0
        for b in base_path:
            if (skipCount > 1):
                auxPath = auxPath + "/" + b
            skipCount = skipCount + 1
        base_path = auxPath
        return auxPath

def process_api_spec(displayName, compartmentId, environment, swagger):
    type = "REST"
    config = oci.config.from_file("config")
    apigateway_client = oci.apigateway.ApiGatewayClient(config)
    logging = oci.loggingingestion.LoggingClient(config)
    #-----------------------------------------------------------------
    try:
        data = swagger
        fullSpec = json.loads(data)

        version = "3"
        try:
            version = (fullSpec["swagger"])[:1]
        except:
            version = (fullSpec["openapi"])[:1]

        print("version", version)

        if (version == "3"):
            endPoint = fullSpec["servers"][0]["url"]
        else:
            endPoint = fullSpec["host"]

        listApis = apigateway_client.list_apis(compartment_id=compartmentId, display_name=displayName, lifecycle_state="ACTIVE")
        apis = json.loads(str(listApis.data))
        c = len(apis["items"])
        api_id = ""

        if (c == 0):
            print("create api")
            create_api_response = apigateway_client.create_api(
                create_api_details=oci.apigateway.models.CreateApiDetails(
                    compartment_id=compartmentId,
                    display_name=displayName,
                    content=data))
            api_created = json.loads(str(create_api_response.data))
            api_id = api_created
        else:
            print("update api")
            update_api_response = apigateway_client.update_api(api_id=apis["items"][0]["id"],
                                                               update_api_details=oci.apigateway.models.UpdateApiDetails(
                                                                   display_name=displayName,
                                                                   content=data))
            api_updated = dict(update_api_response.headers)
            api_id = api_updated

        return api_id

    except(Exception) as ex:
        jsonData = 'error parsing json payload: ' + str(ex)
        put_logs_response = logging.put_logs(
            log_id="ocid1.log.oc1.iad.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            put_logs_details=oci.loggingingestion.models.PutLogsDetails(
                specversion="EXAMPLE-specversion-Value",
                log_entry_batches=[
                    oci.loggingingestion.models.LogEntryBatch(
                        entries=[
                            oci.loggingingestion.models.LogEntry(
                                data="error: " + jsonData,
                                id="ocid1.test.oc1..00000001.EXAMPLE-id-Value")],
                        source="EXAMPLE-source-Value",
                        type="EXAMPLE-type-Value")]))

def DateEncoder(obj):
    if isinstance(obj, datetime.datetime):
        return obj.strftime('%Y-%m-%d')

def is_json(swagger):
    try:
        body = json.loads(swagger)
        return True
    except:
        try:
            yaml_object = yaml.safe_load(swagger) # yaml_object will be a list or a dict
            s = json.dumps(yaml_object, indent=2, default=DateEncoder)
            return False
        except:
            return False

def convert_json(swagger):
    yaml_object = yaml.safe_load(swagger) # yaml_object will be a list or a dict
    return json.dumps(yaml_object, indent=2, default=DateEncoder)

###

def handler(ctx, data: io.BytesIO = None):
    config = oci.config.from_file("config")
    logging = oci.loggingingestion.LoggingClient(config)

    # functions context variables
    app_context = dict(ctx.Config())

    jsonData = ""

    options = getOptions()

    try:
        header = json.loads(data.getvalue().decode('utf-8'))["data"]
        url = options["BaseUrl"]
        body = dict(json.loads(data.getvalue().decode('utf-8')).get("data"))["body"]
        # body content
        swagger = str(body)
        if (is_json(swagger)):
            body = json.loads(body)
        else:
            body = json.loads(convert_json(swagger))
            swagger = convert_json(swagger)

        environment = "DEV"

        # header values
        access_token = header["token"]
        displayName = header["displayName"]
        compartmentId = header['apiCompartmentId']

        authorization = auth_idcs(access_token, url, options["ClientId"], options["ClientSecret"])
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
                log_id="ocid1.log.oc1.iad.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                put_logs_details=oci.loggingingestion.models.PutLogsDetails(
                    specversion="EXAMPLE-specversion-Value",
                    log_entry_batches=[
                        oci.loggingingestion.models.LogEntryBatch(
                            entries=[
                                oci.loggingingestion.models.LogEntry(
                                    data="error: " + jsonData,
                                    id="ocid1.test.oc1..00000001.EXAMPLE-id-Value")],
                            source="EXAMPLE-source-Value",
                            type="EXAMPLE-type-Value")]))

            return response.Response(
                ctx,
                status_code=401,
                response_data=json.dumps({"active": False, "wwwAuthenticate": jsonData})
            )

        # Create API spec
        api_id = process_api_spec(displayName, compartmentId, environment, swagger)

        rdata = json.dumps({
            "active": True,
            "context": {
                "environment": environment,
                "display_name": displayName,
                "api_id": json.dumps(api_id)
            }})

        # put_logs_response = logging.put_logs(
        #     log_id="ocid1.log.oc1.iad.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
        #     put_logs_details=oci.loggingingestion.models.PutLogsDetails(
        #         specversion="EXAMPLE-specversion-Value",
        #         log_entry_batches=[
        #             oci.loggingingestion.models.LogEntryBatch(
        #                 entries=[
        #                     oci.loggingingestion.models.LogEntry(
        #                         data="request payload: " + json.dumps(header),
        #                         id="ocid1.test.oc1..00000001.EXAMPLE-id-Value-1")],
        #                 source="EXAMPLE-source-Value",
        #                 type="EXAMPLE-type-Value")]))


        return response.Response(
            ctx, response_data=rdata,
            status_code=200,
            headers={"Content-Type": "application/json", "data": rdata}
        )

    except(Exception) as ex:
        jsonData = 'error parsing json payload: ' + str(ex)
        put_logs_response = logging.put_logs(
            log_id="ocid1.log.oc1.iad.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            put_logs_details=oci.loggingingestion.models.PutLogsDetails(
                specversion="EXAMPLE-specversion-Value",
                log_entry_batches=[
                    oci.loggingingestion.models.LogEntryBatch(
                        entries=[
                            oci.loggingingestion.models.LogEntry(
                                data="error: " + jsonData + "/" + swagger,
                                id="ocid1.test.oc1..00000001.EXAMPLE-id-Value")],
                        source="EXAMPLE-source-Value",
                        type="EXAMPLE-type-Value")]))

        pass

    return response.Response(
        ctx,
        status_code=401,
        response_data=json.dumps({"active": False, "wwwAuthenticate": jsonData})
    )