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

# DEFINIR AS VARIAVEIS
#
# Método: process_api_spec()
# displayName = "qrcode"
# compartmentId = "ocid1.compartment.oc1..aaaaaaaaqomaaaaaaaaqomaaaaaaaaqomaaaaaaaaqomaaaaaaaaqomaaaaaaaaqom"
# config = oci.config.from_file(profile_name='DEFAULT')
#
# Método: getSpec()
# text_file = open("/Users/cristianohoshikawa/Dropbox/ORACLE/B3/API Gateway/Teste 2024-03-15/qrcode.yaml", "r")

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


def getSpec(name):
    text_file = open(name, "r", encoding='utf-8')
    data = text_file.read()
    text_file.close()

    if (is_json(data)):
        data = data
    else:
        data = convert_json(data)

    return data


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

def accMethods(routes, path, status):
    METHOD = ""
    for spec in routes:
        if (find_path(spec["path"]) == path and spec["backend"]["status"] == status):
            for method in spec["methods"]:
                if (method not in METHOD):
                    METHOD = (METHOD + " " + method).lstrip().upper()
    return METHOD

def accMethods_v2(routes, path, status):
    METHOD = ""
    for spec in routes:
        if (spec["path"] == path and spec["backend"]["status"] == status):
            for method in spec["methods"]:
                if (method not in METHOD):
                    METHOD = (METHOD + " " + method).lstrip().upper()
    return METHOD

def accMethods_v3(routes, path, status):
    METHOD = ""
    for spec in routes:
        if (spec["path"] == path and spec["backend"]["status"] == status):
            for method in spec["methods"]:
                if (method not in METHOD):
                    METHOD = (METHOD + " " + method).lstrip().upper()
    return METHOD

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

def group_by(payload):
    payload = json.loads(payload)
    INFO = sorted(payload, key=key_func)
    result_payload = [ ]
    for key, value in groupby(INFO, key_func):
        list_elements = [ ]
        method_list = ""
        for element in list(value):
            list_elements.append(element)
        for subItem in list_elements:
            item = json.loads(json.dumps(subItem))
            if (item["METHOD"] not in method_list):
                method_list = (method_list + " " + item["METHOD"]).lstrip().upper()
            API_NAME = item["API_NAME"]
            TYPE = item["TYPE"]
            ENVIRONMENT = item["ENVIRONMENT"]
            PATH_PREFIX = item["PATH_PREFIX"]
            PATH = item["PATH"]
            ENDPOINT = item["ENDPOINT"]
            SCHEMA_BODY_VALIDATION = item["SCHEMA_BODY_VALIDATION"]
        result_payload.append({"API_NAME": API_NAME, "TYPE": TYPE, "ENVIRONMENT": ENVIRONMENT, "PATH_PREFIX": PATH_PREFIX, "PATH": PATH, "ENDPOINT": ENDPOINT, "METHOD": method_list, "SCHEMA_BODY_VALIDATION": SCHEMA_BODY_VALIDATION})
    return result_payload

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
                        'CONTENT_TYPE': item2["CONTENT_TYPE"]
                    })

            return list_final
    return json_data_list

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

def replace_escape_chars(obj):
    for k, v in obj.items():
        if isinstance(v, str):
            obj[k] = v.replace('\\\\', '\\"')
        elif isinstance(v, dict):
            obj[k] = replace_escape_chars(v)
        elif isinstance(v, list):
            for i in range(len(v)):
                if isinstance(v[i], str):
                    v[i] = v[i].replace('\\\\', '\\"')
                elif isinstance(v[i], dict):
                    v[i] = replace_escape_chars(v[i])
    return obj

def convert_json(swagger):
    yaml_object = yaml.safe_load(swagger) # yaml_object will be a list or a dict
    x = json.dumps(yaml_object, ensure_ascii=False, indent=2, default=DateEncoder).encode('utf-8')
    return x.decode()

def process_api_spec():
    # displayName = "EXEMPLO"
    compartmentId = "ocid1.compartment.oc1..aaaaaaaaqom2belitvh5ubr342rgzyeycvyg3zt6b4i4owmkzpnpwft37rga"
    environment = "QA"
    type = "REST"
    rate_limit = "2500,CLIENT_IP"

    try:
        rate_config = rate_limit.split(',')
        rate_seconds = int(rate_config[0])
        rate_key = rate_config[1]
        print(rate_seconds)
        print(rate_key)
    except:
        print("erro")


    # Create a default config using DEFAULT profile in default location
    # Refer to
    # https://docs.cloud.oracle.com/en-us/iaas/Content/API/Concepts/sdkconfig.htm#SDK_and_CLI_Configuration_File
    # for more info
    config = oci.config.from_file(profile_name='DEFAULT')

    # TELEMETRY
    # monitoring_client = oci.monitoring.MonitoringClient(config, service_endpoint="https://telemetry-ingestion.us-ashburn-1.oraclecloud.com/20180401")
    #
    # post_metric_data_response = monitoring_client.post_metric_data(
    #     post_metric_data_details=oci.monitoring.models.PostMetricDataDetails(
    #         metric_data=[
    #             oci.monitoring.models.MetricDataDetails(
    #                 namespace="api_customers",
    #                 compartment_id=compartmentId,
    #                 name="customer_request",
    #                 dimensions={
    #                     "customer": "Cliente A"},
    #                 datapoints=[
    #                     oci.monitoring.models.Datapoint(
    #                         timestamp=datetime.strptime(
    #                             datetime.utcnow().isoformat() + 'Z',
    #                             "%Y-%m-%dT%H:%M:%S.%fZ"),
    #                         value=1,
    #                         count=1)],
    #                 resource_group="API_group",
    #                 metadata={
    #                     "metadados": "api"})]))

    # Initialize service client with default config file
    apigateway_client = oci.apigateway.ApiGatewayClient(config)

    # -----------------------------------------------------------------

    arquivo = []
    arquivo.append("/Users/cristianohoshikawa/Dropbox/ORACLE/B3/API Gateway/Testes 2024-03-11/1.0.0-rc2_rcc-interop-agenda_modificado.json")
    arquivo.append("/Users/cristianohoshikawa/Dropbox/ORACLE/B3/API Gateway/Testes 2024-03-11/caso1.yaml")
    arquivo.append("/Users/cristianohoshikawa/Dropbox/ORACLE/B3/API Gateway/Testes 2024-03-11/caso2.yaml")
    arquivo.append("/Users/cristianohoshikawa/Dropbox/ORACLE/B3/API Gateway/Teste 2024-03-15/caso2024-03-15.yaml")
    arquivo.append("/Users/cristianohoshikawa/Dropbox/ORACLE/B3/API Gateway/Teste 2024-03-15/qrcode.yaml")
    #arquivo.append("/Users/cristianohoshikawa/Dropbox/ORACLE/B3/API Gateway/Teste 2024-03-18/1.0.0-rc1_cob 1.yaml")
    arquivo.append("/Users/cristianohoshikawa/Dropbox/ORACLE/B3/API Gateway/Teste 2024-03-18/1.0.0-rc1_cobv.yaml")
    arquivo.append("/Users/cristianohoshikawa/Dropbox/ORACLE/B3/API Gateway/Teste 2024-03-18/1.0.0-rc1_loc.yaml")
    arquivo.append("/Users/cristianohoshikawa/Dropbox/ORACLE/B3/API Gateway/Teste 2024-03-18/1.0.0-rc1_lotecobv.yaml")
    #arquivo.append("/Users/cristianohoshikawa/Dropbox/ORACLE/B3/API Gateway/Teste 2024-03-18/1.0.0-rc1_pix.yaml")
    arquivo.append("/Users/cristianohoshikawa/Dropbox/ORACLE/B3/API Gateway/Teste 2024-03-18/1.0.0-rc1_webhook.yaml")
    arquivo.append("/Users/cristianohoshikawa/Dropbox/ORACLE/B3/API Gateway/Teste 2024-03-20/1.0.0-rc8_cprs.json")
    #arquivo.append("/Users/cristianohoshikawa/Dropbox/ORACLE/B3/API Gateway/Teste 2024-03-21/1.0.0-rc1_cob 1.yaml")
    arquivo.append("/Users/cristianohoshikawa/Dropbox/ORACLE/B3/API Gateway/Teste 2024-03-21/1.0.0-rc2_rcc-interop-agenda.json")
    arquivo.append("/Users/cristianohoshikawa/Dropbox/ORACLE/B3/API Gateway/Teste 2024-03-22/1.0.0-rc8_cprs.json")
    #arquivo.append("/Users/cristianohoshikawa/Dropbox/ORACLE/B3/API Gateway/Teste 2024-03-25/Banco B3/1.0.0-rc1_cob.yaml")
    arquivo.append("/Users/cristianohoshikawa/Dropbox/ORACLE/B3/API Gateway/Teste 2024-06-03/1.0.0-rc1_cob.yaml")
    arquivo.append("/Users/cristianohoshikawa/Dropbox/ORACLE/B3/API Gateway/Teste 2024-06-19/1.0.0-rc1_cob.yaml")
    display = []
    display.append("Interoperabilidades-Agenda")
    display.append("caso-1")
    display.append("caso-2")
    display.append("caso2024-03-15")
    display.append("qrcode")
    #display.append("cob")
    display.append("cobv")
    display.append("loc")
    display.append("lotecobv")
    #display.append("pix")
    display.append("webhook")
    display.append("cprs")
    #display.append("cob1")
    display.append("rcc-interop-agenda")
    display.append("Rural")
    #display.append("cob")
    display.append("pix")
    display.append("GI - Modulo PIX Cob")
    idxArquivo = 0

    while idxArquivo < len(arquivo):

        print("---------------------------------------------------------")
        print(arquivo[idxArquivo])
        print("")

        data = getSpec(arquivo[idxArquivo])
        fullSpec = json.loads(data)

        swagger = str(data)
        swagger2 = str(data)
        if (is_json(swagger)):
            body = json.loads(swagger)
        else:
            body = json.loads(convert_json(swagger2))
            swagger = convert_json(data)

        swagger = swagger

        displayName = display[idxArquivo]

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
        print("url")
        print(endPoint)

        listApis = apigateway_client.list_apis(compartment_id=compartmentId, display_name=displayName,
                                               lifecycle_state="ACTIVE")
        apis = json.loads(str(listApis.data))
        c = len(apis["items"])
        api_id = apis["items"][0]["id"]
        print(api_id)

        try:
            get_api = apigateway_client.get_api_deployment_specification(api_id=api_id)

            api_spec = json.loads(str(get_api.data))
            print(api_spec["routes"])
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
                            #METHOD = accMethods_v3(api_spec["routes"], spec["path"], status)
                        else:
                            fullEndpoint = (endPoint + find_base_path(specPath) + find_path(specPath)).replace("{", "${request.path[").replace("}", "]}")
                            FULL_PATH = specPath
                            ENDPOINT = fullEndpoint
                            PATH = find_path(specPath)
                            PATH_PREFIX = find_base_path(specPath)
                            #METHOD = accMethods(api_spec["routes"], find_path(spec["path"]), status)
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
                        #METHOD = accMethods_v2(api_spec["routes"], PATH, status)

                    OPERATIONID = fullSpec["paths"][spec["path"]][str(spec["methods"][0]).lower()]["operationId"]
                    API_NAME = fullSpec["info"]["title"]
                    if (version == "3"):
                        try:
                            SCHEMA_BODY_VALIDATION = str(fullSpec["paths"][spec["path"]][str(spec["methods"][0]).lower()]["requestBody"]["content"]["application/json"])
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
                        'CONTENT_TYPE': CONTENT_TYPE
                    })
                    print(API_NAME, TYPE, ENVIRONMENT, METHOD, PATH_PREFIX, PATH, ENDPOINT, SCHEMA_BODY_VALIDATION, CONTENT_TYPE)

            json_data_list = verify_path(json_data_list)
            payload = json.dumps(json_data_list)
            #json_data_list = { each['PATH'] : each for each in json_data_list}.values()

            # if (version == "2"):
            #     payload = json.loads(json.dumps(group_by(payload)))
            #     #json_data_list = { each['PATH'] : each for each in payload}.values()
            #payload = json.loads(json.dumps(group_by(payload)))
            payload = json.loads(json.dumps(json_data_list))
            print(payload)
            # migrate_to_apigw(payload, "https://oic-hoshikawa2-idcci5ks1puo-ia.integration.ocp.oraclecloud.com:443/ic/api/integration/v1/flows/rest/MIGRATE_TO_APIGW/1.0/convert", "OIC_SERVICE_USER_BASICAUTH", "e7ae6069-e471-496e-916d-5dc2ae3edac0")
            applyAuthApi(compartmentId=compartmentId, displayName=API_NAME, payload=payload, functionId="", host="", api_gateway_id="", rate_limit=rate_limit)

            c = 0
            idxArquivo = idxArquivo + 1

        except(Exception) as ex:
            print(ex)
            time.sleep(2)


def applyAuthApi(compartmentId, displayName, payload, functionId, host, api_gateway_id, rate_limit):
    config = oci.config.from_file(profile_name='DEFAULT')
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
        if (item["SCHEMA_BODY_VALIDATION"] != ""):
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
            routes.append(
                oci.apigateway.models.ApiSpecificationRoute(
                    path=item["PATH"],
                    backend=oci.apigateway.models.HTTPBackend(
                        type="HTTP_BACKEND",
                        url=callback_url,
                        is_ssl_verify_disabled=False),
                    methods=methods,
                    request_policies=oci.apigateway.models.ApiSpecificationRouteRequestPolicies(
                        header_transformations=oci.apigateway.models.HeaderTransformationPolicy(
                            set_headers=oci.apigateway.models.SetHeaderPolicy(
                                items=[
                                    oci.apigateway.models.SetHeaderPolicyItem(
                                        name="body_schema_validation",
                                        values=[item["SCHEMA_BODY_VALIDATION"]],
                                        if_exists="APPEND")]),
                        )
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
                        header_transformations=oci.apigateway.models.HeaderTransformationPolicy(
                            set_headers=oci.apigateway.models.SetHeaderPolicy(
                                items=[
                                    oci.apigateway.models.SetHeaderPolicyItem(
                                        name="body_schema_validation",
                                        values=[item["SCHEMA_BODY_VALIDATION"]],
                                        if_exists="APPEND")]),
                        )
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
                            'opc-request-id': 'request.headers[opc-request-id]'},
                        cache_key=["token", "opc-request-id"],
                        validation_failure_policy=oci.apigateway.models.ModifyResponseValidationFailurePolicy(
                            type="MODIFY_RESPONSE",
                            response_code="401",
                            response_message="${request.auth[error]}"
                        )
                    )),
                routes=new_routes))
        #creeateOrUpdateDeployment(compartmendId=compartmentId, displayName=displayName + "-validation", validation_deployment_details=validation_deployment_details, create_deployment_details=create_deployment_details, api_gateway_id=api_gateway_id)

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

        #creeateOrUpdateDeployment(compartmendId=compartmentId, displayName=displayName, validation_deployment_details=validation_deployment_details, create_deployment_details=create_deployment_details, api_gateway_id=api_gateway_id)

# Mudar DisplayName e text_file para poder executar
process_api_spec()

# data = getSpec()
# fullSpec = json.loads(data)
# print(fullSpec["paths"]["/v1/credit-rights/{internal_number}"]["get"]["operationId"])
