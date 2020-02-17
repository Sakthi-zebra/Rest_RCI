import pytest
import json
from configparser import ConfigParser
import requests
from RestRCI import *

reader = config.get("readercapabilities", "GetCgf")
reader = reader.split('_')

@pytest.mark.parametrize('command', reader)
def test_post_Getgpio(api, command):
    response = requests.post(api.url, data=command)
    json_resp = json.loads(response.text)
    assert response.status_code == 200 and json_resp["ErrID"] == 0
