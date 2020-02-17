"""
REST client for python customized for RTLS
"""

import os
import json
import jsonschema
import re
import urllib
import http.client
import logging
import simplejson as json
import base64
from urllib.parse import urlparse, urljoin, urlsplit
from prance import ResolvingParser
import mmap
import subprocess
import glob
import configparser
import docker
import pytest

# from urlparse import urlparse,urljoin,urlsplit

__version__ = "0.1"

USER_AGENT = "Python-siesta/%s" % __version__

logging.basicConfig(level=0)

status_code = 0


class Resource(object):
    # TODO: some attrs could be on a inner meta class

    # so Resource can have a minimalist namespace  population
    # and minimize collitions with resource attributes
    def __init__(self, uri, api, ):
        # logging.info("init.uri: %s" % uri)
        self.api = api
        self.uri = uri
        self.scheme, self.host, self.url, z1, z2 = urlsplit(self.api.base_url, self.uri)
        self.id = None
        self.conn = None
        self.headers = {'User-Agent': self.api.user_agent}
        self.attrs = {}
        self._errors = {}

    def __getattr__(self, name):
        """
        Resource attributes (eg: user.name) have priority
        over inner rerouces (eg: users(id=123).applications)
        """
        # logging.info("getattr.name: %s" % name)
        # Reource attrs like: user.name

        if name in self.attrs:
            return self.attrs.get(name)
        # logging.info("self.url: %s" % self.url)
        # TODO Inner resoruces for stuff like: GET /users/{id}/applications
        key = self.uri + '/' + name
        self.api.resources[key] = Resource(uri=key,
                                           api=self.api)
        return self.api.resources[key]

    def __call__(self, id=None):
        # logging.info("call.id: %s" % id)
        # logging.info("call.self.url: %s" % self.url)
        if id == None:
            return self
        self.id = str(id)
        key = self.uri + '/' + self.id
        self.api.resources[key] = Resource(uri=key,
                                           api=self.api)
        return self.api.resources[key]

    # Set the "Accept" request header.
    # +info about request headers:
    # http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html
    def set_request_type(self, mime):
        if mime.lower() == 'json':
            mime = 'application/json'
        elif mime.lower() == 'xml':
            mime = 'application/xml'
        self.headers['Accept'] = mime

    # GET /resource
    # GET /resource/id?arg1=value1&...
    def get(self, **kwargs):
        if self.id == None:
            url = self.url
        else:
            url = self.url + '/' + str(self.id)
        if len(kwargs) > 0:
            url = "%s?%s" % (url, urllib.urlencode(kwargs))
        return self._request("GET", url)

    # POST /resource
    def post(self, **kwargs):
        data = kwargs
        meta = dict([(k, data.pop(k)) for k in data.keys() if k.startswith("__")])
        # print (json.dumps(data))
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        return self._request("POST", self.url, data, headers, meta)

    # PUT /resource/id
    def put(self, data):  # **kwargs):

        url = self.url  # + '/' + str(self.id)
        # data = kwargs
        meta = ''  # dict([(k, data.pop(k)) for k in data.keys() if k.startswith("__")])
        headers = {"Content-Type": "application/zip"}
        return self._request("PUT", url, data, headers, meta)

    # DELETE /resource/id
    def delete(self, id, **kwargs):
        url = self.url + '/' + str(id)
        data = kwargs
        meta = dict([(k, data.pop(k)) for k in data.keys() if k.startswith("__")])
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        return self._request(url, "DELETE", data, headers, meta)

    def _request(self, method, url, body='', headers={}, meta={}):

        global status_code

        if self.scheme == "http":
            self.conn = http.client.HTTPConnection(self.host)
        elif self.scheme == "https":
            self.conn = http.client.HTTPSConnection(self.host)

        if str(self.api.auth_type) == 'Basic':
            userAndPass = base64.b64encode(self.api.username + b':' + self.api.password).decode("ascii")
            headers = {'Authorization': 'Basic %s' % userAndPass}

        if not 'User-Agent' in headers:
            headers['User-Agent'] = self.headers['User-Agent']

        if not 'Accept' in headers and 'Accept' in self.headers:
            headers['Accept'] = self.headers['Accept']

        complete_url = urljoin(self.scheme + '://' + self.host, url + self.uri)

        if method == "POST":
            body = json.dumps(body)
        elif method == "PUT":
            f = open(body, 'rb')
            body = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
            headers['Content-Length'] = len(body)

        print("\nURL                       : ", complete_url)
        print("\nHEADER                    : ", headers)
        print("\nBODY                      : ", body)

        self.conn.request(method=method, url=complete_url, body=body, headers=headers)
        content = self.conn.getresponse()

        status_code = content.status
        print("\nHTTP Response Code        : ", status_code)
        print("\nHTTP Response Reason      : ", content.reason)
        return content


class API(object):
    def __init__(self, base_url, user_agent="Python-siesta/%s" % __version__,
                 auth=None, auth_type="Basic", username=None, password=None,
                 consumer_key=None, consumer_token=None,
                 ):
        self.base_url = base_url + '/' if not base_url.endswith('/') else base_url
        self.api_path = urlparse(base_url).path
        self.resources = {}
        self.request_type = None
        self.auth_type = auth_type
        self.user_agent = user_agent
        # self.username = b"rtlsadmin"
        # self.password = b"Z@@t$R1l$"
        self.username = b"rtlsdebug"
        self.password = b"rt75d3bug"

        if not os.path.exists('rtls_resolved.json'):
            self.resolve_schema()

    def set_request_type(self, mime):
        self.request_type = mime
        # set_request_type for every instantiated resources:
        for resource in self.resources:
            self.resources[resource].set_request_type(mime)

    def __getattr__(self, name):
        # logging.info("API.getattr.name: %s" % name)

        key = name
        if not key in self.resources:
            # logging.info("Creating resource with uri: %s" % key)
            self.resources[key] = Resource(uri=key, api=self, )
        return self.resources[key]

    def validate(self, response, resourceid, api_method, api=None):

        global status_code

        output = response.read().decode()

        print("\nHTTP Response             : ", output)

        if api_method == 'post' or api_method == 'put':
            if output == 'null':
                return True
            elif "No changes in config" in output:
                return True
            else:
                return False
        else:
            if output == '':
                return False

        resource = resourceid.replace('/', '_')  # To find the associated schema file for the input api
        # print (resource)

        resource = re.sub('\d+$', '', resource)

        if 'location_analytics' in resource and any(x in resource for x in ['error', 'warning']):
            resource = re.sub('\d+.', 'laid_', resource)

        elif 'radio_c_and_d' in resource and any(x in resource for x in ['error', 'warning']):
            resource = re.sub('\d+.', 'cndid_', resource)

        elif not any(x in resource for x in ['location_analytics', 'radio_c_and_d']):
            resource = re.sub('\d+.', 'aarid_', resource)  # Same schema applicable even though aar id is given

        else:
            resource = re.sub('\d+.', '', resource)

        # print (resource)

        schema_path = glob.glob(os.path.abspath('schemas/' + api_method + '_' + resource + '*.json'))

        print('\nSchemas                               : ', schema_path[0])

        try:
            with open(schema_path[0], 'r') as f:
                schema_data = json.loads(f.read())
        except FileNotFoundError:
            print("\nSkipping schema validation")
            return True

        try:

            schema = schema_data['responses'][str(status_code)]['content']['application/json'][
                'schema']  # ['properties']

            # print ("\nSchema                                     : ", json.dumps(schema))
            # print (jsonschema.validate(output,schema))
            #
            # v = jsonschema.Draft3Validator((json.dumps(schema))).validate(output)
            #
            # for error in sorted(v.iter_errors(output), key=str):
            #     print(error.message)
            #     if any(item in error.message for item in
            #            [".0 is not of type 'integer'", "is not of type 'array'", "is not of type 'object'"]):
            #         print ("Skip this error")
            #         pass
            #     else:
            #         print ("Schema Validation Failed    : ", str(error.message))
            #         assert False, "Schema Validation Failed"
            #         return False

            try:
                output = json.loads(output)
                jsonschema.validate(output, schema)
            except Exception as error:
                print("\n", error.message)
                if any(item in error.message for item in
                       [".0 is not of type 'integer'", "is not of type 'array'", "is not of type 'object'"]):
                    print("Skip this error")
                    pass
                else:
                    print("\nSchema Validation Failed    : ", str(error.message))
                    return False
            # Lazily report all errors in the instance
            try:
                v = jsonschema.Draft3Validator(schema)

                for error in sorted(v.iter_errors(output), key=str):
                    # print("\n",error.message)
                    if any(item in error.message for item in
                           [".0 is not of type 'integer'", "is not of type 'array'", "is not of type 'object'"]):
                        # print ("Skip this error")
                        pass
                    else:
                        print("\nSchema Validation Failed    : ", str(e.message))
                        return False
            except AttributeError:
                pass
            except Exception as e:
                print("\n", e.message)
                print("\nSchema Validation Failed    : ", str(e.message))
                return False


        except KeyError as e:
            if api_method == "post" and status_code == 200 and 'content' in str(e):
                pass

        validate_data(output, resourceid)

        if status_code == 200:
            return True

        return False

    def generate_schema(self, output='schemas'):
        """
        Converts a valid OpenAPI specification into a set of JSON Schema files
        """
        with open('rtls_resolved.json') as f:
            data = json.load(f)

        if not os.path.exists(output):
            os.makedirs(output)

        print("\nGenerating individual schemas")

        for title in data['paths']:
            specification = {}
            name = title[1:].lower()
            # print (name)

            for api_method in data['paths'][title]:
                try:
                    print("\nProcessing %s" % name)
                    schema_file_name = "%s_%s.json" % (api_method, name)
                    schema_file_name = re.sub('[{}]', '', schema_file_name)
                    schema_file_name = schema_file_name.replace('/', '_')
                    specification['responses'] = data['paths'][title][api_method]['responses']

                    if api_method == 'get':
                        for resp_code in specification['responses']:

                            try:
                                properties = \
                                specification['responses'][resp_code]['content']['application/json']['schema'][
                                    'properties']
                                req_list = []

                                for item in properties:
                                    req_list.append(item)

                                # print ('*******************',req_list,'*******************')

                                specification['responses'][resp_code]['content']['application/json']['schema'][
                                    'required'] = req_list
                                # print ("ADDED 1")

                                try:
                                    for req_item in req_list:

                                        try:

                                            properties = \
                                            specification['responses'][resp_code]['content']['application/json'][
                                                'schema']['properties'][req_item]['items']['properties']
                                            req_list = []

                                            for item in properties:
                                                req_list.append(item)

                                            # print ('*******************', req_list, '*******************')

                                            specification['responses'][resp_code]['content']['application/json'][
                                                'schema']['properties'][req_item]['items']['required'] = req_list
                                            # print ("ADDED 2")

                                        except:
                                            pass
                                except:
                                    pass

                            except:
                                properties = \
                                specification['responses'][resp_code]['content']['application/json']['schema']['items'][
                                    'properties']
                                req_list = []
                                for item in properties:
                                    req_list.append(item)

                                # print ('####################', req_list, '####################')
                                # print (req_list)

                                specification['responses'][resp_code]['content']['application/json']['schema']['items'][
                                    'required'] = req_list
                                # print ("ADDED 3")

                    with open("%s/%s" % (output, schema_file_name), 'w') as schema_file:
                        print("\nGenerating %s" % schema_file_name)
                        schema_file.write(json.dumps(specification, indent=2))
                except Exception as e:
                    print("\nAn error occured processing %s: %s" % (title, e))

        return True

    def resolve_schema(self):

        # Copy rtls_api_json spec file from httpd container to host
        # os.system("docker cp rtls-httpd-container:/usr/local/apache2/htdocs/rtls_api_spec.json .")

        # parser = ResolvingParser(self.base_url[:-8] + 'doc/rtls_api_spec.json',backend='openapi-spec-validator')
        parser = ResolvingParser('rtls_api_spec.json', backend='openapi-spec-validator')

        with open("%s" % ("rtls_resolved.json"), 'w') as schema_file:
            print("\nGenerating rtls_resolved.json")
            schema_file.write(json.dumps(parser.specification, indent=2))

        response = os.popen("prance validate --backend=openapi-spec-validator 'rtls_resolved.json'").read()
        print("\n", response)
        assert "Validates OK as OpenAPI 3.0.0!" in response
        return self.generate_schema()

    def copy_kafka_log(self):
        if os.path.exists('00000000000000000000.log'):
            os.remove('00000000000000000000.log')
        if os.path.exists('kafka_topic.txt'):
            os.remove('kafka_topic.txt')

        output = subprocess.getoutput('docker ps -aqf "name=kafka-docker-secure_kafka_1"')
        path = "/kafka/kafka-logs-" + output + "/rtls.tag_location_testing.v2.json-0/00000000000000000000.log ."

        # Copy kafka log file from kafka to host
        os.system("docker cp kafka-docker-secure_kafka_1:" + path)

        if os.path.exists('00000000000000000000.log'):
            print(subprocess.getoutput('cat 00000000000000000000.log | strings -n 8 > kafka_topic.txt'))
            return True
        return False

    def parse_kafka_log(self):
        assert self.copy_kafka_log()
        line = subprocess.check_output(['tail', '-1', 'kafka_topic.txt'])
        try:
            return (json.loads(line.decode()))
        except:
            return {}


class validate_data(object):
    config = configparser.ConfigParser()
    config_rtls_data = {}
    aar_location_data = {}
    Host_address = {}

    def __new__(cls, response, query):
        # hasattr method checks if the class object an instance property or not.
        if not hasattr(cls, 'instance'):

            os.system("docker cp rtls_config:/usr/share/rtls/config/rtls.conf .")
            os.system("docker cp rtls_config:/usr/share/rtls/config/aar_info.csv .")

            cls.config.read('rtls.conf')
            sections = cls.config.sections()
            for section in sections:
                la_list = ['la_time_filter', 'la_confidence_filter', 'la_velocity_filter', 'la_id_filter_num_bytes',
                           'la_distance_filter']
                for key in cls.config[section]:
                    if section == 'location_analytics' and key in la_list:
                        cls.config_rtls_data[key] = float(cls.config[section][key])
                    else:
                        cls.config_rtls_data[key] = cls.config[section][key]

            with open('aar_info.csv', 'r') as file:
                next(file)
                aar_id = 0
                for line in file:
                    words = line.strip('\n').split(',')
                    dict = {'id': aar_id,
                            'position': {'x': float(words[2]), 'y': float(words[3]), 'z': float(words[4])},
                            'orientation': float(words[5])}
                    cls.aar_location_data[aar_id] = dict
                    cls.Host_address[aar_id] = {'host_address': words[0]}
                    aar_id += 1

            cls.instance = super(validate_data, cls).__new__(cls)
        return cls.instance

    def __init__(self, response, query):
        self.response = response
        self.query = query
        self.calling_method()

    def get__validate_config(self):
        # print (self.response)
        print(validate_data.config_rtls_data)
        assert validate_data.config_rtls_data == self.response
        return True

    def get_validate_aar_location(self):
        # print("going to validate aar location file")
        no_aar = len(self.response['locations'])
        for aar_id in range(no_aar):
            if self.response['locations'][aar_id]['id'] == aar_id:
                assert self.aar_location_data[aar_id] == self.response['locations'][aar_id]
        return True

    def get_validate_aar_network(self):
        # print("going to validate the network api")
        no_aar = len(self.response['networks'])
        for aar_id in range(no_aar):
            # self.Host_address[aar_id]['host_address']==self.response['networks'][aar_id]['host_name']
            # print(self.Host_address[aar_id]['host_address'])
            # print(self.response['networks'][aar_id]['host_name'])
            if self.response['networks'][aar_id]['id'] == aar_id:
                assert self.Host_address[aar_id]['host_address'] == self.response['networks'][aar_id]['host_name']
        return True

    def get_validate_aar_status(self):
        # print("going to validate aar status")
        no_aar = len(self.response['statuses'])
        for aar_id in range(no_aar):
            aar_statuses = {'connected', 'updating'}
            if self.response['statuses'][aar_id]['id'] == aar_id:
                assert self.response['statuses'][aar_id]['status'] in aar_statuses
                assert self.response['statuses'][aar_id]['ntp']['reach'] == 377
                assert 0 <= self.response['statuses'][aar_id]['cpu']['user'] <= 100
                assert 0 <= self.response['statuses'][aar_id]['cpu']['system'] <= 100
        return True

    def get_validate_status(self):
        # print("Going to validate status")
        assert (0 <= self.response['error_message_count'] <= 3000)
        assert (0 <= self.response['warning_message_count'] <= 3000)
        assert (0 <= self.response['cpu_util'] <= 100)
        assert (0 <= self.response['mem_util'] <= 100)
        return True

    def get_validate_la_filter(self):
        # print("goint to validate la filters")
        no_aar = len(self.response)
        for aar_id in range(no_aar):
            assert (self.response[aar_id]['velocity_thresh'] == int(self.config_rtls_data['la_velocity_filter']))
            assert (self.response[aar_id]['confidence_thresh'] == self.config_rtls_data['la_confidence_filter'])
            assert (self.response[aar_id]['time_thresh'] == self.config_rtls_data['la_time_filter'])
            assert (self.response[aar_id]['dist_thresh'], self.config_rtls_data['la_distance_filter'])
            assert (self.response[aar_id]['static_or_dynamic'] == self.config_rtls_data['la_static_or_dynamic_filter'])

            assert (self.response[aar_id]['id_filter']['filter'] == self.config_rtls_data['la_id_filter'])
            assert (self.response[aar_id]['id_filter']['mask'] == self.config_rtls_data['la_id_filter_mask'])
            assert (self.response[aar_id]['id_filter']['num_bytes'] == int(
                self.config_rtls_data['la_id_filter_num_bytes']))
        return True

    def get_validate_la_units(self):
        # print(base_url)
        no_aar = len(self.response)
        for aar_id in range(no_aar):
            assert (self.response[aar_id]['units'] == (self.config_rtls_data['location_analytics_config_units']))
        return True

    def get_validate_la_reporting(self):
        # print("going to validate reporting fields")
        test_dict = {
            "confidence": "OFF",
            "report_source": "OFF",
            "readers": "OFF",
            "timestamp": "OFF",
            "site_id": "OFF",
            "direction": "OFF",
            "static_or_dynamic": "OFF",
            "epc_id": "OFF",
            "velocity": "OFF",
            "position": "OFF",
            "message_id": "OFF"
        }
        no_aar = len(self.response)
        for aar_id in range(no_aar):
            print(self.response[aar_id].pop('id'))
            reporting = self.config_rtls_data['location_analytics_reporting_fields'].split(',')
            for report in reporting:
                if report in test_dict: test_dict[report] = "ON"
            assert (test_dict == self.response[aar_id])
        return True

    def get_validate_LA_status(self):

        if self.config_rtls_data['centralized_or_distributed'] == 'centralized':
            assert (len(self.response) == 1)
            assert (self.response[0]['standby'] == False)
            assert (0 <= self.response[0]['cpu_util'] <= 100)
            assert (0 <= self.response[0]['mem_util'] <= 100)
            assert (self.response[0]['messages_in'] >= self.response[0]['messages_out'])
        else:
            count_stand_by = 0
            standby = lambda x: 1 if x == 0 and len(self.aar_location_data) > 1 else x
            expected_standby_count = standby(int(len(self.aar_location_data) * 0.05))
            for aar_id in range(len(self.aar_location_data)):
                if self.response[aar_id]['standby'] == True: count_stand_by += 1
                assert (0 <= self.response[0]['cpu_util'] <= 100)
                assert (0 <= self.response[0]['mem_util'] <= 100)
                assert (self.response[0]['messages_in'] >= self.response[0]['messages_out'])
            assert count_stand_by == expected_standby_count
        assert (len(self.aar_location_data) == len(self.response))
        return True

    def get_validate_host_sw_update(self, base_url):
        query = ['aar/status']
        print(base_url)
        response = API
        print(response)
        for aar_id in range(len(self.aar_location_data)):
            print(self.response['progresses'][aar_id]['progress'])
        return True

    api_dic = {'location_analytics/status': get_validate_LA_status,
               'location_analytics/reporting': get_validate_la_reporting,
               'location_analytics/units': get_validate_la_units, 'location_analytics/filters': get_validate_la_filter,
               'status': get_validate_status, 'config': get__validate_config, 'aar/location': get_validate_aar_location,
               'aar/status': get_validate_aar_status, r'aar/network': get_validate_aar_network}

    def calling_method(self):
        print("\n****************** Validating " + self.query + "******************\n")
        try:
            assert validate_data.api_dic[self.query](self)
        except KeyError:
            print("Validation pending")
        print("\n*******************************************************\n")
        # self.api_dic[self.query](self)
