#!/usr/bin/env python
# encoding: utf-8

import requests

# pull in the cacert.pem file that we're currently using and put it where requests expects it to be
datas = [(requests.certs.where(), 'requests/')]
