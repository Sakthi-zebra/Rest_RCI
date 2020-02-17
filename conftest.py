import pytest
import RestRCI
import logging
import json
import os
import sys


@pytest.fixture(scope='module')
def log():
    LOG_FORMAT = "%(asctime)s %(name)s: %(levelname)s %(message)s"


@pytest.fixture(scope='session', autouse=True)
def api():
    '''
    pytest RESTRCI server fixture that can be used in all test scripts to get access to server instance.
    '''
    api = RestRCI.rest()
    print(api.url)
    f = open("restRCI_summary.txt", "w")
    return api
