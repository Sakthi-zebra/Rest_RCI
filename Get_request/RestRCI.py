"""
rest api automation: this automation code is for fx9600 series readers
author : vs6993
"""

import requests
import json
import logging
from configparser import ConfigParser
import pytest


class rest:
    global ip, endpoint, protocal, url

    def __init__(self):
        '''
        Setting protocal , ip , endpoint and URL
        '''
        self.con = ConfigParser()
        self.con.read("setting.ini")
        self.ip = self.con.get('config', 'ip')
        self.endpoint = self.con.get('config', 'endpoint')
        self.protocal = self.con.get('config', 'protocal')
        # self.header = self.con.get('config','')
        self.url = self.protocal + "://" + self.ip + "/" + self.endpoint

    @pytest.mark.parametrize('input', 'output', [
        ({"Cmd": "GetInfo", "Fields": "All"},
         {"Report": "GetInfo", "RdrSN": "84:24:8D:FB:6C:10", "RdrModel": "96004", "Version": "3.6.10.0"}),
        ({"Cmd": "GetInfo", "Fields": ["RdrSN"]}, {"Report": "GetInfo", "RdrSN": "84:24:8D:FB:6C:10"}),
        ({"Cmd": "GetInfo", "Fields": ["RdrModel"]}, {"Report": "GetInfo", "RdrModel": "96004"}),
        ({"Cmd": "GetInfo", "Fields": ["Version"]}, {"Report": "GetInfo", "Version": "3.6.10.0"})
    ])
    def get_Reader_Info(self, command, exp_response):
        # self.payload = self.con.get('commands','readerInfo')
        # print(self.payload)
        self.resp = requests.post(self.url, command)
        print(self.resp.status_code)
        print(json.loads(self.resp.text))  # changing to dict obj

        self.validate(self.payload, self.resp.text, dict(exp_response))

    def validate(self, payload, act_responce, exp_response):
        # expresponse = json.loads(self.con.get('response','Getinifo'))
        actresponce = json.loads(act_responce)
        # matching key and values
        a = {k: actresponce[k] for k in actresponce if k in exp_response and actresponce[k] == exp_response[k]}
        print(a)


if __name__ == '__main__':
    obj = rest()
    # obj.get_Reader_Info()
    print(getattr(obj, "ip"))
