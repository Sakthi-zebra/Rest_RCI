import pytest
import json
from configparser import ConfigParser
import requests
from RestRCI import *

reader = config.get("readerinfo", "getinfo")
reader = reader.split('_')


@pytest.mark.parametrize('command', reader)
def test_post_Getgpio(api, command):
    get_Rest_response(api,command)

