"""
rest api automation: this automation code is for fx9600 series readers
author : vs6993
"""
import json
import logging
from configparser import ConfigParser
import requests

config = ConfigParser()
config.read("setting.ini")


def get_Rest_response(api,data):
    response = requests.post(api.url, data=data)
    json_resp = json.loads(response.text)
    print(json_resp)
    response_code = requests.status_codes
    ERROR_ID = json_resp['ErrID']
    if ERROR_ID == 0:
        return response_code
    else:
        print(ERROR_CODES[ERROR_ID])
        return ERROR_CODES[ERROR_ID]


class rest:
    global ip, endpoint, protocal, url

    def __init__(self):
        '''
        setting protocal , ip , endpoint and URL
        '''
        self.con = ConfigParser()
        self.con.read("setting.ini")
        self.ip = self.con.get('config', 'ip')
        self.endpoint = self.con.get('config', 'endpoint')
        self.protocol = self.con.get('config', 'protocol')
        # self.header = self.con.get('config','')
        self.url = self.protocol + "://" + self.ip + "/" + self.endpoint

    def validate(self, payload, act_response, exp_response):

        actresponse = json.loads(act_response)
        exp_response = json.loads(exp_response)

        if actresponse.items() - exp_response.items():
            return False
        else:
            return True


ERROR_CODES = {
    0: 'No Error',
    1: 'Bad message',
    2: 'CRC error',
    3: 'Buffer full',
    4: 'Response too big',
    5: 'Memory overrun',
    6: 'Reader too cold',
    7: 'Reader hot',
    8: 'Reader too hot',
    20: 'Command not supported',
    21: 'Field not supported',
    22: 'Field value not supported',
    23: 'Field value changed',
    24: 'GPIO toggle value the same',
    25: 'GPIO not settable',
    26: 'Trigger not an input switch',
    30: 'SpotProfiles full',
    31: 'SpotProfile error',
    32: 'Illegal SpotProfile',
    33: 'ThisTag timeout',
    34: 'Spot error',
    40: 'ReadZones full',
    41: 'ReadZone start error',
    42: 'ReadZone definition error',
    1001: 'GPIO apis failed',
    1002: 'Unhandled Exception while processing request',
    1003: "Singulation settings GET/SET failed",
    1004: "AntennaConfig settings GET/SET failed",
    1005: "No Tag URL registered",
    1006: "Unknown exception while posting tags",
    1007: "Add prefilter API failed"
}
