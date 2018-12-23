#!/usr/bin/env python3

import yaml
import sys
import re
import json

from os import listdir
from os.path import isfile, join
from requests.auth import HTTPBasicAuth


###############################################################################
############################# ATCutils ########################################
###############################################################################

class ATCutils:
    """Class which consists of handful methods used throughout the project"""

    def __init__(self):
        """Init method"""

        pass

    @staticmethod
    def read_rule_file(path):
        """Open the file and load it to the variable. Return text"""

        with open(path) as f:
            rule_text = f.read()

        return rule_text

    @staticmethod
    def read_yaml_file(path):
        """Open the yaml file and load it to the variable. 
        Return created list"""

        with open(path) as f:
            yaml_fields = yaml.load_all(f.read())

        buff_results = [x for x in yaml_fields]
        if len(buff_results) > 1:
            result = buff_results[0]
            result['additions'] = buff_results[1:]
        else:
            result = buff_results[0]
        return result

    @staticmethod
    def load_yamls(path):
        """Load multiple yamls into list"""

        yamls = [
            join(path, f) for f in listdir(path) 
            if isfile(join(path, f)) 
            if f.endswith('.yaml') 
            or f.endswith('.yml')
            ]

        result = []

        for yaml in yamls:
            try:
                result.append(read_yaml_file(yaml))

            except ScannerError:
                raise ScannerError('yaml is bad! %s' % yaml)

        return result

    @staticmethod
    def confluence_get_page_id(apipath, auth, space, title):
        """Get confluence page ID based on title and space"""
        
        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
            }

        url = apipath + "content"
        space_page_url = url + '?spaceKey=' + space + '&title=' \
            + title + '&expand=space'

        response = requests.request(
           "GET",
           space_page_url,
           headers=headers,
           auth=auth
        )

        response = response.json()

        # Check if response contains proper information and return it if so
        if response.hasattr(u'results'):
            if type(response[u'results']) == list:
                if response[u'results'][0].hasattr(u'id'):
                    return response[u'results'][0][u'id']

        # If page not found
        return None

    @staticmethod
    def push_to_confluence(data, apipath, auth):

        apipath = apipath if apipath[-1] == '/' else apipath+'/'

        url = apipath + "content"

        headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
            }

        alldata = True
        for i in ["title", "spacekey", "parentid", "confluencecontent"]:
            if i not in data.keys():
                alldata = False
        if not alldata:
            raise Exception("Not all data were provided in order " +
                            "to push the content to confluence")

        dict_payload = {
            "title": "%s" % data["title"], # req
            "type": "page", # req
            "space": { # req
                "key": "%s" % data["spacekey"]
                },
            "status": "current",
            "ancestors": [
                {
                  "id": "%s" % data["parentid"] # parent id
                }
                ],
            "body": { # req
                "storage": {
                    "value": "%s" % data["confluencecontent"], 
                    "representation": "storage"
                    }
                }
            }

        payload = json.dumps(dict_payload)

        response = requests.request(
            "POST",
            url,
            data=payload,
            headers=headers,
            auth=auth
            )

        resp = json.loads(response.text)

        if "data" in resp.keys():
            if "successful" in resp["data"].keys() 
                    and bool(resp["data"]["successful"]):
                return "Page created"

            else:
                cid = get_page_id(
                    apipath, auth, data["spacekey"],
                    data["title"]
                    )

            response = requests.request(
                "GET",
                url + "/%s?expand=body.storage" % str(cid),
                data=payload,
                headers=headers,
                auth=auth
                )

            resp = json.loads(response.text)

            current_content = resp["body"]["storage"]["value"]

            if current_content == data["confluencecontent"]:
                return "No update required"

            response = requests.request(
                "GET",
                url + "/%s/version" % str(cid),
                data=payload,
                headers=headers,
                auth=auth
                )

            resp = json.loads(response.text)

            i = 0

            for item in resp["results"]:
                if int(item["number"]) > i:
                    i = int(item["number"])

            i += 1 #update by one

            dict_payload["version"] = {"number": "%s" % str(i)}
            payload = json.dumps(dict_payload)

            response = requests.request(
                "PUT",
                url + "/%s" % str(cid),
                data=payload,
                headers=headers,
                auth=auth
                )

            return "Page updated"

        elif "status" in resp.keys():
            if resp["status"] == "current":
                return "Page created"

        return "Something unexpected happened.."

    @staticmethod
    def map_sigma_logsource_fields_to_real_world_names(logsource_dict):
        """Get sigma logsource dict and rename key/values into our model, 
        so we could use it for Data Needed calculation"""

        proper_logsource_dict = logsource_dict

        sigma_to_real_world_mapping = {
            'sysmon': 'Microsoft-Windows-Sysmon/Operational',
            'security': 'Security',
            'system': 'System',
            'product': 'platform',
            'windows': 'Windows',
            'service': 'channel'
            }

        # @yugoslavskiy: I am not sure about this 
        # list(proper_logsource_dict.items()) loop. but it works -.-
        # I was trying to avoid error "dictionary changed size during iteration"
        # which was triggered because of iteration 
        # over something that we are changing

        for old_key, old_value in list(proper_logsource_dict.items()):

            for new_key, new_value in sigma_to_real_world_mapping.items():

                if old_key == new_key:
                    # here we do mapping of keys and values
                    new_key_name = sigma_to_real_world_mapping[new_key]
                    new_value_name = sigma_to_real_world_mapping[old_value]
                    proper_logsource_dict[new_key_name] \
                        = proper_logsource_dict.pop(old_key)
                    proper_logsource_dict.update(
                        [(sigma_to_real_world_mapping[new_key], new_value_name)]
                        )

        return proper_logsource_dict


###############################################################################
############################# Data Needed #####################################
###############################################################################

class DataNeeded:
    """Class for the Data Needed entity"""

    def __init__(self, yaml_file):
        """Init method"""

        # Init vars (unnecessary?)
        self.title = None
        self.description = None
        self.loggingpolicy = None
        self.platform = None
        self.type = None
        self.channel = None
        self.provider = None
        self.fields = None
        self.sample = None
        self.dataneeded_parsed_file = None

        # Init methods
        self.parse_into_fields(yaml_file)

    @classmethod
    def parse_into_fields(cls, yaml_file):
        """Description"""

        cls.dataneeded_parsed_file = ATCutils.read_yaml_file(yaml_file)

        """Fill the fields with values. Put None if not value found"""
        cls.title = cls.dataneeded_parsed_file.get("title")
        cls.description = cls.dataneeded_parsed_file.get("description")
        cls.loggingpolicy = cls.dataneeded_parsed_file.get("loggingpolicy")
        cls.platform = cls.dataneeded_parsed_file.get("platform")
        cls.type = cls.dataneeded_parsed_file.get("type")
        cls.channel = cls.dataneeded_parsed_file.get("channel")
        cls.provider = cls.dataneeded_parsed_file.get("provider")
        cls.fields = cls.dataneeded_parsed_file.get("fields")
        cls.sample = cls.dataneeded_parsed_file.get("sample")


###############################################################################
############################# Logging Policy ##################################
###############################################################################

class LoggingPolicy:
    """Class for the Detection Rule entity"""

    def __init__(self, yaml_file):
        """Init method"""

        # Init methods
        self.parse_into_fields(yaml_file)

    @classmethod
    def parse_into_fields(cls, yaml_file):
        """Description"""

        cls.loggingpolicy_parsed_file = ATCutils.read_yaml_file(yaml_file)


###############################################################################
############################# Enrichments #####################################
###############################################################################

class Enrichments:
    """Class for the Detection Rule entity"""

    def __init__(self, yaml_file):
        """Init method"""

        # Init methods
        self.parse_into_fields(yaml_file)

    @classmethod
    def parse_into_fields(cls, yaml_file):
        """Description"""

        cls.enrichments_parsed_file = ATCutils.read_yaml_file(yaml_file)


###############################################################################
############################# Detection Rule ##################################
###############################################################################

class DetectionRule:
    """Class for the Detection Rule entity"""

    def __init__(self, yaml_file):
        """Init method"""

        # Init methods
        self.parse_into_fields(yaml_file)

    @classmethod
    def parse_into_fields(cls, yaml_file):
        """Description"""

        cls.detectionrule_parsed_file = ATCutils.read_yaml_file(yaml_file)


###############################################################################
############################# If exectued #####################################
###############################################################################

if __name__ == "__main__":
    """If file is executed"""

    DataNeeded("../dataneeded/DN_0001_windows_process_creation_4688.yml")
