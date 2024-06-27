import base64
import json
import io
from fdk import response
import oci
import requests
import time
from itertools import groupby
import yaml
import datetime
import ast

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

def find_base_path(strPath):
    base_path = strPath.split('/')[1]
    if (len(base_path) == 0):
        base_path = strPath
    else:
        base_path = "/" + base_path
    return base_path

def has_path_endpoint(endPoint):
    endPointAux = endPoint.replace("//", "#")
    endPointSplited = endPointAux.split('/')
    if (len(endPointSplited) > 1):
        return True
    else:
        return False

def concatSplited(endPointSplited):
    count = 0
    endPointStr = ""
    for item in endPointSplited:
        if (count > 0):
            endPointStr = endPointStr + "/" + item
        count = count + 1
    return endPointStr

def find_base_pathendpoint(endPoint, strPath):
    base_path = strPath.split('/')[1]
    if (len(base_path) == 0 and has_path_endpoint(endPoint)):
        endPointAux = endPoint.replace("//", "#")
        endPointSplited = endPointAux.split('/')
        if (len(endPointSplited) > 1):
            endPointSplitedStr = concatSplited(endPointSplited)
            if (endPointSplitedStr != None):
                base_path = endPointSplitedStr
            else:
                base_path = strPath
        else:
            base_path = strPath
    else:
        endPointAux = endPoint.replace("//", "#")
        endPointSplited = endPointAux.split('/')
        if (len(endPointSplited) > 1):
            endPointSplitedStr = concatSplited(endPointSplited)
            if (endPointSplitedStr != None):
                base_path = endPointSplitedStr
                endPoint = endPointSplited[0].replace("#", "//")
            else:
                base_path = "/" + base_path
        else:
            base_path = "/" + base_path
    return base_path


def find_base_endpoint(endPoint):
    endPointAux = endPoint.replace("//", "#")
    endPointSplited = endPointAux.split('/')
    if (len(endPointSplited) > 1):
        endPointSplitedStr = endPointSplited[1]
        if (endPointSplitedStr != None):
            endPoint = endPointSplited[0].replace("#", "//")
    return endPoint

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

def removeLastSlash(path):
    return path.rstrip("/")

def creeateOrUpdateDeployment(compartmendId, displayName, validation_deployment_details, create_deployment_details, api_gateway_id):
    config = oci.config.from_file("config")
    apigateway_client = oci.apigateway.DeploymentClient(config)
    listGateway = apigateway_client.list_deployments(compartment_id=compartmendId, display_name=displayName, lifecycle_state="ACTIVE")
    gateway = json.loads(str(listGateway.data))
    ind = -1
    c = -1
    if (len(gateway) > 0):
        c = 0
        for item in gateway["items"]:
            if (item["gateway_id"] == api_gateway_id):
                ind = c
                break
            c = c + 1
    if (gateway["items"] != [] and c > -1 and ind > -1):
        gateway_id = gateway["items"][ind]["gateway_id"]
        deployment_id = gateway["items"][ind]["id"]
    else:
        gateway_id = api_gateway_id
        deployment_id = ""

    if (gateway["items"] != [] and deployment_id != ""):
        apigateway_client.update_deployment(deployment_id=deployment_id, update_deployment_details=validation_deployment_details)
    else:
        apigateway_client.create_deployment(create_deployment_details=create_deployment_details)

def applyAuthApi(compartmentId, displayName, payload, functionId, host, api_gateway_id, rate_limit):
    config = oci.config.from_file("config")
    logging = oci.loggingingestion.LoggingClient(config)
    apigateway_client = oci.apigateway.DeploymentClient(config)
    listGateway = apigateway_client.list_deployments(compartment_id=compartmentId, display_name=displayName, lifecycle_state="ACTIVE")
    gateway = json.loads(str(listGateway.data))
    ind = -1
    c = -1
    if (len(gateway) > 0):
        c = 0
        for item in gateway["items"]:
            if (item["gateway_id"] == api_gateway_id):
                ind = c
                break
            c = c + 1
    if (gateway["items"] != [] and c > -1 and ind > -1):
        gateway_id = gateway["items"][ind]["gateway_id"]
        deployment_id = gateway["items"][ind]["id"]
    else:
        gateway_id = api_gateway_id
        deployment_id = 0

    try:
        rate_config = rate_limit.split(',')
        rate_seconds = int(rate_config[0])
        rate_key = rate_config[1]
        rate_limiting = oci.apigateway.models.RateLimitingPolicy(
            rate_in_requests_per_second=rate_seconds,
            rate_key=rate_key)
    except:
        rate_limiting = None

    path_prefix = "/"
    routes = [ ]
    new_routes = [ ]
    for item in payload:
        methods = [item["METHOD"]]
        path_prefix = item["PATH_PREFIX"]
        callback_url = ("https://" + host + item["PATH_PREFIX"] + "validation-callback" + item["PATH"]).replace("{", "${request.path[").replace("}", "]}")
        item_policy = []
        item_query = []
        item_header = []
        if (item["SCHEMA_BODY_VALIDATION"] != ""):
            item_policy.append(oci.apigateway.models.SetHeaderPolicyItem(
                name="body_schema_validation",
                values=[item["SCHEMA_BODY_VALIDATION"]],
                if_exists="APPEND"))
        if (item["SCHEMA_QUERY_VALIDATION"] != ""):
            item_policy.append(oci.apigateway.models.SetHeaderPolicyItem(
                name="query_schema_validation",
                values=[item["SCHEMA_QUERY_VALIDATION"]],
                if_exists="APPEND"))
            try:
                for items in ast.literal_eval(item["SCHEMA_QUERY_VALIDATION"]):
                    if (items["in"] == "query"):
                        item_query.append(oci.apigateway.models.QueryParameterValidationItem(
                            name=items["name"],
                            required=items["required"]
                        ))
                    if (items["in"] == "header"):
                        item_header.append(oci.apigateway.models.HeaderValidationItem(
                            name=items["name"],
                            required=items["required"]
                        ))
            except:
                print("NO")

        if (item["SCHEMA_BODY_VALIDATION"] != "" or item["SCHEMA_QUERY_VALIDATION"] != ""):
            put_logs_response = logging.put_logs(
                log_id="ocid1.log.oc1.iad.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                put_logs_details=oci.loggingingestion.models.PutLogsDetails(
                    specversion="EXAMPLE-specversion-Value",
                    log_entry_batches=[
                        oci.loggingingestion.models.LogEntryBatch(
                            entries=[
                                oci.loggingingestion.models.LogEntry(
                                    data="callback_url: " + callback_url,
                                    id="ocid1.test.oc1..00000001.EXAMPLE-id-Value")],
                            source="EXAMPLE-source-Value",
                            type="EXAMPLE-type-Value")]))

            header_transformation = None
            query_parameter_validation = None
            header_validation = None
            if (len(item_policy) >0):
                header_transformation=oci.apigateway.models.HeaderTransformationPolicy(
                    set_headers=oci.apigateway.models.SetHeaderPolicy(
                        items=item_policy))
            if (len(item_query) > 0):
                query_parameter_validation=oci.apigateway.models.QueryParameterValidationRequestPolicy(
                    parameters=item_query
                )
            if (len(item_header) > 0):
                header_validation=oci.apigateway.models.HeaderValidationRequestPolicy(
                    headers=item_header
                )

            routes.append(
                oci.apigateway.models.ApiSpecificationRoute(
                    path=item["PATH"],
                    backend=oci.apigateway.models.HTTPBackend(
                        type="HTTP_BACKEND",
                        url=callback_url,
                        is_ssl_verify_disabled=False),
                    methods=methods,
                    request_policies=oci.apigateway.models.ApiSpecificationRouteRequestPolicies(
                        header_transformations=header_transformation,
                        query_parameter_validations=query_parameter_validation,
                        header_validations=header_validation
                    )))
            new_routes.append(
                oci.apigateway.models.ApiSpecificationRoute(
                    path=item["PATH"],
                    backend=oci.apigateway.models.HTTPBackend(
                        type="HTTP_BACKEND",
                        url=item["ENDPOINT"],
                        is_ssl_verify_disabled=False),
                    methods=methods,
                    request_policies=oci.apigateway.models.ApiSpecificationRouteRequestPolicies(
                        header_transformations=header_transformation,
                        query_parameter_validations=query_parameter_validation,
                        header_validations=header_validation
                    )
                ))
        else:
            routes.append(
                oci.apigateway.models.ApiSpecificationRoute(
                    path=item["PATH"],
                    backend=oci.apigateway.models.HTTPBackend(
                        type="HTTP_BACKEND",
                        url=callback_url,
                        is_ssl_verify_disabled=False),
                    methods=methods))
            new_routes.append(
                oci.apigateway.models.ApiSpecificationRoute(
                    path=item["PATH"],
                    backend=oci.apigateway.models.HTTPBackend(
                        type="HTTP_BACKEND",
                        url=item["ENDPOINT"],
                        is_ssl_verify_disabled=False),
                    methods=methods))


    if (new_routes != [ ]):
        validation_deployment_details=oci.apigateway.models.UpdateDeploymentDetails(
            display_name=displayName + "-validation",
            specification=oci.apigateway.models.ApiSpecification(
                request_policies=oci.apigateway.models.ApiSpecificationRequestPolicies(
                    rate_limiting=rate_limiting,
                    authentication=oci.apigateway.models.CustomAuthenticationPolicy(
                        type="CUSTOM_AUTHENTICATION",
                        function_id=functionId,
                        is_anonymous_access_allowed=False,
                        parameters={
                            'token': 'request.headers[token]',
                            'body': 'request.body',
                            'body_schema_validation': 'request.headers[body_schema_validation]',
                            'query_schema_validation': 'request.headers[query_schema_validation]',
                            'opc-request-id': 'request.headers[opc-request-id]'},
                        cache_key=["token", "opc-request-id"],
                        validation_failure_policy=oci.apigateway.models.ModifyResponseValidationFailurePolicy(
                            type="MODIFY_RESPONSE",
                            response_code="401",
                            response_message="${request.auth[error]}"
                        )
                    )),
                routes=new_routes))
        create_deployment_details=oci.apigateway.models.CreateDeploymentDetails(
            display_name=displayName + "-validation",
            compartment_id=compartmentId,
            gateway_id=gateway_id,
            path_prefix= path_prefix + "validation-callback",
            specification=oci.apigateway.models.ApiSpecification(
                request_policies=oci.apigateway.models.ApiSpecificationRequestPolicies(
                    rate_limiting=rate_limiting,
                    authentication=oci.apigateway.models.CustomAuthenticationPolicy(
                        type="CUSTOM_AUTHENTICATION",
                        function_id=functionId,
                        is_anonymous_access_allowed=False,
                        parameters={
                            'token': 'request.headers[token]',
                            'body': 'request.body',
                            'body_schema_validation': 'request.headers[body_schema_validation]',
                            'query_schema_validation': 'request.headers[query_schema_validation]',
                            'opc-request-id': 'request.headers[opc-request-id]'},
                        cache_key=["token", "opc-request-id"],
                        validation_failure_policy=oci.apigateway.models.ModifyResponseValidationFailurePolicy(
                            type="MODIFY_RESPONSE",
                            response_code="401",
                            response_message="${request.auth[error]}"
                        )
                    )),
                routes=new_routes))
        creeateOrUpdateDeployment(compartmendId=compartmentId, displayName=displayName + "-validation", validation_deployment_details=validation_deployment_details, create_deployment_details=create_deployment_details, api_gateway_id=api_gateway_id)

    if (routes != [ ]):
        # The 1st layer will not authenticate
        validation_deployment_details=oci.apigateway.models.UpdateDeploymentDetails(
            display_name=displayName,
            specification=oci.apigateway.models.ApiSpecification(
                request_policies=oci.apigateway.models.ApiSpecificationRequestPolicies(
                    rate_limiting=rate_limiting),
                routes=routes))

        create_deployment_details=oci.apigateway.models.CreateDeploymentDetails(
            display_name=displayName,
            compartment_id=compartmentId,
            gateway_id=gateway_id,
            path_prefix= path_prefix,
            specification=oci.apigateway.models.ApiSpecification(
                request_policies=oci.apigateway.models.ApiSpecificationRequestPolicies(
                    rate_limiting=rate_limiting),
                routes=routes))

        creeateOrUpdateDeployment(compartmendId=compartmentId, displayName=displayName, validation_deployment_details=validation_deployment_details, create_deployment_details=create_deployment_details, api_gateway_id=api_gateway_id)

def check_endpoint(schemes, endpoint):
    if (schemes == ""):
        if (endpoint.find("http://") == -1 and endpoint.find("https://") == -1):
            endpoint = "https://" + endpoint
    else:
        if (endpoint.find("http://") == -1 and endpoint.find("https://") == -1):
            if (schemes.find("://") == -1):
                endpoint = schemes + "://" + endpoint
            else:
                endpoint = schemes + endpoint
    return endpoint

def key_func(k):
    return k['PATH']

def verify_path(json_data_list):
    list_final = []
    for item in json_data_list:
        if (item["PATH"] == ""):
            for item2 in json_data_list:
                if (item2["PATH"] == ""):
                    list_final.append({
                        'API_NAME': item2["API_NAME"],
                        'TYPE': item2["TYPE"],
                        'ENVIRONMENT': item2["ENVIRONMENT"],
                        'METHOD': item2["METHOD"],
                        'PATH_PREFIX': "/",
                        'PATH': item2["PATH_PREFIX"],
                        'ENDPOINT': item2["ENDPOINT"],
                        'SCHEMA_BODY_VALIDATION': item2["SCHEMA_BODY_VALIDATION"],
                        'SCHEMA_QUERY_VALIDATION': item2["SCHEMA_QUERY_VALIDATION"],
                        'CONTENT_TYPE': item2["CONTENT_TYPE"]
                    })
                else:
                    list_final.append({
                        'API_NAME': item2["API_NAME"],
                        'TYPE': item2["TYPE"],
                        'ENVIRONMENT': item2["ENVIRONMENT"],
                        'METHOD': item2["METHOD"],
                        'PATH_PREFIX': item2["PATH_PREFIX"],
                        'PATH': item2["PATH"],
                        'ENDPOINT': item2["ENDPOINT"],
                        'SCHEMA_BODY_VALIDATION': item2["SCHEMA_BODY_VALIDATION"],
                        'SCHEMA_QUERY_VALIDATION': item2["SCHEMA_QUERY_VALIDATION"],
                        'CONTENT_TYPE': item2["CONTENT_TYPE"]
                    })

            return list_final
    return json_data_list

def process_api_spec(api_id, compartmentId, environment, swagger, functionId, host, api_gateway_id, rate_limit):
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

        get_api = apigateway_client.get_api_deployment_specification(api_id=api_id, opc_request_id="DEPLOY-0001")

        api_spec = json.loads(str(get_api.data))

        json_data_list = []

        endPointOrigin = endPoint
        for spec in api_spec["routes"]:
            status = spec["backend"]["status"]
            specPath = spec["path"]

            for method in spec["methods"]:
                METHOD = method.lstrip().upper()

                if (version == "3"):
                    if (has_path_endpoint(endPointOrigin)):
                        endPoint = find_base_endpoint(endPointOrigin)
                        specPath = (find_base_pathendpoint(endPointOrigin, specPath)).replace("//", "/")
                        fullEndpoint = (endPoint + specPath + spec["path"]).replace("{", "${request.path[").replace("}", "]}")
                        FULL_PATH = specPath
                        ENDPOINT = fullEndpoint
                        PATH = spec["path"]
                        PATH_PREFIX = specPath
                    else:
                        fullEndpoint = (endPoint + find_base_path(specPath) + find_path(specPath)).replace("{", "${request.path[").replace("}", "]}")
                        FULL_PATH = specPath
                        ENDPOINT = fullEndpoint
                        PATH = find_path(specPath)
                        PATH_PREFIX = find_base_path(specPath)
                else:
                    schemes = ""
                    try:
                        schemes = fullSpec["schemes"][0]
                    except:
                        schemes = "https"

                    fullEndpoint = check_endpoint(schemes, (endPoint + removeLastSlash(fullSpec["basePath"]) + spec["path"]).replace("{", "${request.path[").replace("}", "]}"))
                    FULL_PATH = fullSpec["basePath"] + spec["path"]
                    ENDPOINT = fullEndpoint
                    PATH = spec["path"]
                    PATH_PREFIX = removeLastSlash(fullSpec["basePath"])

                OPERATIONID = fullSpec["paths"][spec["path"]][str(spec["methods"][0]).lower()]["operationId"]
                API_NAME = fullSpec["info"]["title"]
                if (version == "3"):
                    try:
                        try:
                            reference = str(fullSpec["paths"][spec["path"]][str(spec["methods"][0]).lower()]["requestBody"]["content"]["application/json"]["schema"]["$ref"]).replace("#/components/schemas/", "")
                            SCHEMA_BODY_VALIDATION = reference + "," + api_id
                        except:
                            reference = str(fullSpec["paths"][spec["path"]][str(spec["methods"][0]).lower()]["requestBody"]["content"]["application/json"])
                            SCHEMA_BODY_VALIDATION = reference
                        CONTENT_TYPE = "application/json"
                    except:
                        SCHEMA_BODY_VALIDATION = ""
                        CONTENT_TYPE = ""
                else:
                    SCHEMA_BODY_VALIDATION = ""
                    CONTENT_TYPE = ""
                    try:
                        reference = str(fullSpec["paths"][spec["path"]][str(spec["methods"][0]).lower()]["parameters"][0]["schema"]["$ref"]).replace("#/definitions/", "")
                        SCHEMA_BODY_VALIDATION = reference + "," + api_id
                        CONTENT_TYPE = "application/json"
                    except:
                        SCHEMA_BODY_VALIDATION = ""
                        CONTENT_TYPE = ""

                # 2024-06-26 - Query Parameter
                if (version == "3"):
                    try:
                        try:
                            reference = str(fullSpec["paths"][spec["path"]][str(spec["methods"][0]).lower()]["parameters"])
                            SCHEMA_QUERY_VALIDATION = reference #+ "," + api_id
                        except:
                            reference = str(fullSpec["paths"][spec["path"]][str(spec["methods"][0]).lower()]["parameters"])
                            SCHEMA_QUERY_VALIDATION = reference
                        CONTENT_TYPE = "application/json"
                    except:
                        SCHEMA_QUERY_VALIDATION = ""
                        CONTENT_TYPE = ""
                else:
                    SCHEMA_QUERY_VALIDATION = ""
                    CONTENT_TYPE = ""
                    try:
                        reference = str(fullSpec["paths"][spec["path"]][str(spec["methods"][0]).lower()]["parameters"])
                        SCHEMA_QUERY_VALIDATION = reference #+ "," + api_id
                        CONTENT_TYPE = "application/json"
                    except:
                        SCHEMA_QUERY_VALIDATION = ""
                        CONTENT_TYPE = ""

                TYPE = type
                ENVIRONMENT = environment
                json_data_list.append({
                    'API_NAME': API_NAME,
                    'TYPE': TYPE,
                    'ENVIRONMENT': ENVIRONMENT,
                    'METHOD': METHOD,
                    'PATH_PREFIX': PATH_PREFIX,
                    'PATH': PATH,
                    'ENDPOINT': ENDPOINT,
                    'SCHEMA_BODY_VALIDATION': SCHEMA_BODY_VALIDATION,
                    'SCHEMA_QUERY_VALIDATION': SCHEMA_QUERY_VALIDATION,
                    'CONTENT_TYPE': CONTENT_TYPE
                })

                print(API_NAME, TYPE, ENVIRONMENT, METHOD, PATH_PREFIX, PATH, ENDPOINT, SCHEMA_BODY_VALIDATION, SCHEMA_QUERY_VALIDATION, CONTENT_TYPE)
                put_logs_response = logging.put_logs(
                    log_id="ocid1.log.oc1.iad.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                    put_logs_details=oci.loggingingestion.models.PutLogsDetails(
                        specversion="EXAMPLE-specversion-Value",
                        log_entry_batches=[
                            oci.loggingingestion.models.LogEntryBatch(
                                entries=[
                                    oci.loggingingestion.models.LogEntry(
                                        data="api deployment: " + json.dumps({
                                            'API_NAME': API_NAME,
                                            'TYPE': TYPE,
                                            'ENVIRONMENT': ENVIRONMENT,
                                            'METHOD': METHOD,
                                            'PATH_PREFIX': PATH_PREFIX,
                                            'PATH': PATH,
                                            'ENDPOINT': ENDPOINT,
                                            'SCHEMA_BODY_VALIDATION': SCHEMA_BODY_VALIDATION,
                                            'SCHEMA_QUERY_VALIDATION': SCHEMA_QUERY_VALIDATION,
                                            'CONTENT_TYPE': CONTENT_TYPE
                                        }),
                                        id="ocid1.test.oc1..00000001.EXAMPLE-id-Value")],
                                source="EXAMPLE-source-Value",
                                type="EXAMPLE-type-Value")]))


        json_data_list = verify_path(json_data_list)
        payload = json.dumps(json_data_list)
        put_logs_response = logging.put_logs(
            log_id="ocid1.log.oc1.iad.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            put_logs_details=oci.loggingingestion.models.PutLogsDetails(
                specversion="EXAMPLE-specversion-Value",
                log_entry_batches=[
                    oci.loggingingestion.models.LogEntryBatch(
                        entries=[
                            oci.loggingingestion.models.LogEntry(
                                data="json_data_list: " + payload,
                                id="ocid1.test.oc1..00000001.EXAMPLE-id-Value")],
                        source="EXAMPLE-source-Value",
                        type="EXAMPLE-type-Value")]))

        payload = json.loads(json.dumps(json_data_list))
        print(payload)
        applyAuthApi(compartmentId=compartmentId, displayName=API_NAME, payload=payload, functionId=functionId, host=host, api_gateway_id=api_gateway_id, rate_limit=rate_limit)

    except(Exception) as ex:
        raise

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
        api_id = header["apiId"]
        host = header["host_name"]
        compartmentId = header['apiCompartmentId']
        functionId = header['functionId']
        api_gateway_id = header['apiGatewayId']
        rate_limit = header['rateLimit']

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
                log_id="ocid1.log.oc1.iad.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
                put_logs_details=oci.loggingingestion.models.PutLogsDetails(
                    specversion="EXAMPLE-specversion-Value",
                    log_entry_batches=[
                        oci.loggingingestion.models.LogEntryBatch(
                            entries=[
                                oci.loggingingestion.models.LogEntry(
                                    data="error(1): " + jsonData,
                                    id="ocid1.test.oc1..00000001.EXAMPLE-id-Value")],
                            source="EXAMPLE-source-Value",
                            type="EXAMPLE-type-Value")]))

            return response.Response(
                ctx,
                status_code=401,
                response_data=json.dumps({"active": False, "wwwAuthenticate": jsonData})
            )

        # Create API spec
        process_api_spec(api_id=api_id, compartmentId=compartmentId, environment=environment, swagger=swagger, functionId=functionId, host=host, api_gateway_id=api_gateway_id, rate_limit=rate_limit)

        rdata = json.dumps({
            "active": True,
            "context": {
                "environment": environment,
                "api_id": api_id
            }})

        return response.Response(
            ctx, response_data=rdata,
            status_code=200,
            headers={"Content-Type": "application/json", "apiId": api_id, "environment": environment}
        )

    except(Exception) as ex:
        jsonData = 'error parsing json payload: ' + str(ex)
        put_logs_response = logging.put_logs(
            log_id="ocid1.log.oc1.iad.xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            put_logs_details=oci.loggingingestion.models.PutLogsDetails(
                specversion="EXAMPLE-specversion-Value",
                log_entry_batches=[
                    oci.loggingingestion.models.LogEntryBatch(
                        entries=[
                            oci.loggingingestion.models.LogEntry(
                                data="error(2): " + jsonData,
                                id="ocid1.test.oc1..00000001.EXAMPLE-id-Value")],
                        source="EXAMPLE-source-Value",
                        type="EXAMPLE-type-Value")]))

        pass

    return response.Response(
        ctx,
        status_code=401,
        response_data=json.dumps({"active": False, "wwwAuthenticate": jsonData})
    )