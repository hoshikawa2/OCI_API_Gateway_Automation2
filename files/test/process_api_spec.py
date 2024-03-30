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
# text_file = open("/Teste 2024-03-15/teste1.yaml", "r")

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
    text_file = open(name, "r")
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

def convert_json(swagger):
    yaml_object = yaml.safe_load(swagger) # yaml_object will be a list or a dict
    return json.dumps(yaml_object, indent=2, default=DateEncoder)


def process_api_spec():
    # displayName = "EXEMPLO"
    compartmentId = "ocid1.compartment.oc1..aaaaaaaaqomaaaaaaaaqomaaaaaaaaqomaaaaaaaaqomaaaaaaaaqomaaaaaaaaqom"
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
    arquivo.append("/Teste 2024-03-15/teste1.yaml")
    arquivo.append("/Testes 2024-03-11/teste2.json")
    arquivo.append("/Testes 2024-03-11/teste3.yaml")
    arquivo.append("/Testes 2024-03-11/teste4.yaml")
    arquivo.append("/Teste 2024-03-15/teste5.yaml")
    arquivo.append("/Teste 2024-03-18/teste6.yaml")
    arquivo.append("/Teste 2024-03-18/teste7.yaml")
    arquivo.append("/Teste 2024-03-18/teste8.yaml")
    arquivo.append("/Teste 2024-03-18/teste9.yaml")
    arquivo.append("/Teste 2024-03-18/teste10.yaml")
    arquivo.append("/Teste 2024-03-18/teste11.yaml")
    arquivo.append("/Teste 2024-03-20/teste12.json")
    arquivo.append("/Teste 2024-03-21/teste13.yaml")
    arquivo.append("/Teste 2024-03-21/teste14.json")
    arquivo.append("/Teste 2024-03-22/teste15.json")
    arquivo.append("/Teste 2024-03-25/teste16.yaml")
    display = []
    display.append("caso1")
    display.append("caso2")
    display.append("caso3")
    display.append("caso4")
    display.append("caso5")
    display.append("caso6")
    display.append("caso7")
    display.append("caso8")
    display.append("caso9")
    display.append("caso10")
    display.append("caso11")
    display.append("caso12")
    display.append("caso13")
    display.append("caso14")
    display.append("caso15")
    display.append("caso16")

    idxArquivo = 0

    while idxArquivo < len(arquivo):

        print("---------------------------------------------------------")
        print(arquivo[idxArquivo])
        print("")

        data = getSpec(arquivo[idxArquivo])
        fullSpec = json.loads(data)

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

                if (version == "3"):
                    if (has_path_endpoint(endPointOrigin)):
                        endPoint = find_base_endpoint(endPointOrigin)
                        specPath = (find_base_pathendpoint(endPointOrigin, specPath)).replace("//", "/")
                        fullEndpoint = (endPoint + specPath + spec["path"]).replace("{", "${request.path[").replace("}", "]}")
                        FULL_PATH = specPath
                        ENDPOINT = fullEndpoint
                        PATH = spec["path"]
                        PATH_PREFIX = specPath
                        METHOD = accMethods_v3(api_spec["routes"], spec["path"], status)
                    else:
                        fullEndpoint = (endPoint + find_base_path(specPath) + find_path(specPath)).replace("{", "${request.path[").replace("}", "]}")
                        FULL_PATH = specPath
                        ENDPOINT = fullEndpoint
                        PATH = find_path(specPath)
                        PATH_PREFIX = find_base_path(specPath)
                        METHOD = accMethods(api_spec["routes"], find_path(spec["path"]), status)
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
                    METHOD = accMethods_v2(api_spec["routes"], PATH, status)

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
            json_data_list = { each['PATH'] : each for each in json_data_list}.values()

            # if (version == "2"):
            #     payload = json.loads(json.dumps(group_by(payload)))
            #     #json_data_list = { each['PATH'] : each for each in payload}.values()
            payload = json.loads(json.dumps(group_by(payload)))
            print(payload)
            # migrate_to_apigw(payload, "https://teste.integration.ocp.oraclecloud.com:443/ic/api/integration/v1/flows/rest/MIGRATE_TO_APIGW/1.0/convert", "OIC_SERVICE_USER_BASICAUTH", "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")

            c = 0
            idxArquivo = idxArquivo + 1

        except(Exception) as ex:
            print(ex)
            time.sleep(2)

# Mudar DisplayName e text_file para poder executar
process_api_spec()

# data = getSpec()
# fullSpec = json.loads(data)
# print(fullSpec["paths"]["/v1/credit-rights/{internal_number}"]["get"]["operationId"])
