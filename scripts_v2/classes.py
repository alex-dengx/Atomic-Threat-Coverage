#!/usr/bin/env python3

import yaml
import sys
import re
import json
import os
import subprocess

from os import listdir
from os.path import isfile, join
from requests.auth import HTTPBasicAuth
from jinja2 import Environment, FileSystemLoader


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
        """Description"""

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
    def sigma_lgsrc_fields_to_names(logsource_dict):
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

    @staticmethod
    def main_dn_calculatoin_func(dr_file_path):
        """you need to execute this function to calculate DN for DR file"""

        dn_list = APTutils.load_yamls('../dataneeded')

        # detectionrule \
        # = read_yaml_file("../detectionrules/sigma_win_susp_run_locations.yml")
        detectionrule = APTutils.read_yaml_file(dr_file_path)

        no_extra_logsources = bool

        """For every DataNeeded file we do:
        * for every DN_ID in detectionrule check if its in DataNeeded Title
        * if there is no "additions" (extra log sources), make entire alert an
        "addition" (to process it in the same way)
        """

        if detectionrule.get('additions') is None:

            detectionrule['additions'] = [detectionrule]
            no_extra_logsources = True

        logsource = {}

        if no_extra_logsources is True:

            final_list = []
            # we work only with one logsource. let's add it to our dict
            product = detectionrule['logsource']['product']
            service = detectionrule['logsource']['service']
            logsource.update([('product', product), ('service', service)])

            """ then we need to collect all eventIDs 
            and calculate Data Needed PER SELECTION
            """

            for _field in detectionrule['detection']:
              # if it is selection field
              if "selection" in str(_field):
                dr_dn = detectionrule['detection'][_field]
                final_list.append(
                    APTutils.calculate_dn_for_dr(
                        dn_list, dr_dn, logsource
                    )
                )       
            return final_list

        else:
        """ if there are multiple logsources, let's work with them separately.
        first grab general field from first yaml document (usually, commandline)
        """
            common_fields = []
            final_list = []

            for fields in detectionrule['detection']['selection']:
                common_fields.append(fields)

            # then let's calculate Data Needed per different logsources
            for addition in detectionrule['additions']:

                product = addition['logsource']['product']
                service = addition['logsource']['service']
                logsource.update([('product', product), ('service', service)])
                
                """ then we need to collect all eventIDs 
                and calculate Data Needed PER SELECTION
                """

                for _field in addition['detection']:
                # if it is selection field
                    if "selection" in str(_field):
                        dr_dn = addition['detection'][_field]
                        #dr_dn.update(logsource)

                        for field in common_fields:
                            dr_dn.update([(field, 'placeholder')])

                            result_of_dn_caclulation \
                                = APTutils.calculate_dn_for_dr(
                                    dn_list, dr_dn, logsource
                                    )

                            for dn in result_of_dn_caclulation:
                                if dn not in final_list:
                                    final_list.append(dn)

        return final_list

    @staticmethod
    def calculate_dn_for_dr(
        dict_of_dn_files, dict_of_logsource_fields_from_dr, dr_logsource_dict
    ):
        """Description"""

        dn_list = dict_of_dn_files
        dr_dn = dict_of_logsource_fields_from_dr
        logsource = dr_logsource_dict

        list_of_DN_matched_by_fields = []
        list_of_DN_matched_by_fields_and_logsource = []
        list_of_DN_matched_by_fields_and_logsource_and_eventid = []

        for dn in dn_list:
            # Will create a list of keys from Detection Rule fields dictionary
            list_of_DR_fields = [*dr_dn] 
            list_of_DN_fields = dn['fields']
            amount_of_fields_in_DR = len(list_of_DR_fields)

            amount_of_intersections_betw_DR_and_DN_fields = len(
                set(list_of_DR_fields).intersection(list_of_DN_fields)
                )

            if amount_of_intersections_betw_DR_and_DN_fields \
                    == amount_of_fields_in_DR:
                # if they are equal, do..
                list_of_DN_matched_by_fields.append(dn['title'])

        for dn in dn_list:

            for matched_dn in list_of_DN_matched_by_fields:

                if dn['title'] == matched_dn:

                    # divided into two lines due to char limit
                    proper_logsource \
                        = APTutils.sigma_lgsrc_fields_to_names(logsource)

                    amount_of_fields_in_logsource = len([*proper_logsource])
                    y = dn
                    x = proper_logsource
                    # превозмогая трудности!
                    shared_items \
                        = {k: x[k] for k in x if k in y and x[k] == y[k]}
                    if len(shared_items) == amount_of_fields_in_logsource:

                        # divided into two lines due to char limit
                        list_of_DN_matched_by_fields_and_logsource\
                            .append(dn.get('title'))

        # and only in the last step we check EventID
        if dr_dn['EventID'] != None:

            eventID = dr_dn['EventID']

            for dn in dn_list:

                if dn['title'] in list_of_DN_matched_by_fields_and_logsource:

                    if dn['title'].endswith(str(eventID)):

                        # divided into two lines due to char limit
                        list_of_DN_matched_by_fields_and_logsource_and_eventid\
                            .append(dn.get('title'))

            return list_of_DN_matched_by_fields_and_logsource_and_eventid

        else:

            return list_of_DN_matched_by_fields_and_logsource

    @staticmethod
    def write_file(path, content, options="w+"):
        """Simple method for writing content to some file"""

        with open(path, options) as file:
            # write content
            file.write(content)

        return True

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

        # self.fields contains parsed fields obtained from yaml file
        self.fields = None

        self.yaml_file = yaml_file

        # The name of the directory containing future markdown DataNeeded
        self.parent_title = "Data_Needed"

        # Init methods
        self.parse_into_fields(self.yaml_file)

    @classmethod
    def parse_into_fields(cls, yaml_file):
        """Description"""

        # cls.fields contains parsed fields obtained from yaml file
        cls.fields = ATCutils.read_yaml_file(yaml_file)

        """Fill the fields with values. Put None if key not found"""
        cls.title = cls.dataneeded_parsed_file.get("title")
        cls.description = cls.dataneeded_parsed_file.get("description")
        cls.loggingpolicy = cls.dataneeded_parsed_file.get("loggingpolicy")
        cls.platform = cls.dataneeded_parsed_file.get("platform")
        cls.type = cls.dataneeded_parsed_file.get("type")
        cls.channel = cls.dataneeded_parsed_file.get("channel")
        cls.provider = cls.dataneeded_parsed_file.get("provider")
        cls.fields = cls.dataneeded_parsed_file.get("fields")
        cls.sample = cls.dataneeded_parsed_file.get("sample")

    @classmethod
    def render_markdown_template(cls):
        """Description"""

        # Point to the templates directory
        env = Environment(loader=FileSystemLoader('templates'))

        # Get DataNeeded template
        template = env.get_template('markdown_dataneeded_template.md.j2')

        cls.fields.update({'description':cls.fields.get('description').strip()}) 

        cls.content = template.render(cls.fields)

        return True

    @classmethod
    def save_markdown_file(cls):
        """Write content (md template filled with data) to a file"""

        base = os.path.basename(cls.yaml_file)
        title = os.path.splitext(base)[0]

        file_path = '../Atomic_Threat_Coverage/' + cls.parent_title  +"/" + 
           title + ".md"

        return ATCutils.write_file(file_path, cls.content)
        

###############################################################################
############################# Logging Policy ##################################
###############################################################################

class LoggingPolicy:
    """Class for the Detection Rule entity"""

    def __init__(self, yaml_file):
        """Init method"""

        # Init vars
        self.yaml_file = yaml_file
        # The name of the directory containing future markdown LogginPolicy
        self.parent_title = "Logging_Policies"

        # Init methods
        self.parse_into_fields(self.yaml_file)

    @classmethod
    def parse_into_fields(cls, yaml_file):
        """Description"""

        # cls.fields contains parsed fields obtained from yaml file
        cls.fields = ATCutils.read_yaml_file(cls.yaml_file)

    @classmethod
    def render_markdown_template(cls):
        """Description"""

        # Point to the templates directory
        env = Environment(loader=FileSystemLoader('templates'))

        # Get DataNeeded template
        template = env.get_template('markdown_loggingpolicy_template.md.j2')
        
        # get rid of newline to not mess with table in md
        cls.fields.update({'description':cls.fields.get('description').strip()}) 

        cls.content = template.render(cls.fields)

        return True

    @classmethod
    def save_markdown_file(cls):
        """Write content (md template filled with data) to a file"""

        base = os.path.basename(cls.yaml_file)
        title = os.path.splitext(base)[0]

        file_path = '../Atomic_Threat_Coverage/' + cls.parent_title  +"/" + 
           title + ".md"

        return ATCutils.write_file(file_path, cls.content)


###############################################################################
############################# Enrichments #####################################
###############################################################################

class Enrichments:
    """Class for the Detection Rule entity"""

    def __init__(self, yaml_file):
        """Init method"""

        # Init vars
        self.yaml_file = yaml_file
        # The name of the directory containing future markdown LogginPolicy
        self.parent_title = "Enrichments"

        # Init methods
        self.parse_into_fields(self.yaml_file)

    @classmethod
    def parse_into_fields(cls, yaml_file):
        """Description"""

        cls.enrichments_parsed_file = ATCutils.read_yaml_file(yaml_file)

    @classmethod
    def render_markdown_template(cls):
        """Description"""
        
        pass

    @classmethod
    def save_markdown_file(cls):
        """Write content (md template filled with data) to a file"""

        base = os.path.basename(cls.yaml_file)
        title = os.path.splitext(base)[0]

        file_path = '../Atomic_Threat_Coverage/' + cls.parent_title  +"/" + 
           title + ".md"

        return ATCutils.write_file(file_path, cls.content)


###############################################################################
############################# Detection Rule ##################################
###############################################################################

class DetectionRule:
    """Class for the Detection Rule entity"""

    def __init__(self, yaml_file):
        """Init method"""

        # Init vars
        self.yaml_file = yaml_file

        # The name of the directory containing future markdown DetectionRules
        self.parent_title = "Detection_Rules"

        # Init methods
        self.parse_into_fields()

    @classmethod
    def parse_into_fields(cls):
        """Description"""

        # cls.fields contains parsed fields obtained from yaml file
        cls.fields = ATCutils.read_yaml_file(cls.yaml_file)

    @classmethod
    def render_markdown_template(cls):
        """Render template with data in it"""

        # Point to the templates directory
        env = Environment(loader=FileSystemLoader('templates'))

        # Get DetectionRule template
        template = env.get_template('markdown_alert_template.md.j2')

        # Read raw sigma rule
        sigma_rule = ATCutils.read_rule_file(cls.yaml_file)

        # Put raw sigma rule into fields var
        cls.fields.update({'sigma_rule':sigma_rule})

        # Define which queries we want from Sigma
        queries = ["es-qs", "xpack-watcher", "graylog"]

        # Convert sigma rule into queries (for instance, graylog query)
        for query in queries:
            # prepare command to execute from shell
            cmd = "../detectionrules/sigma/tools/sigmac -t " +
                output + " --ignore-backend-errors " + cls.yaml_file

            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)

            (query, err) = p.communicate()

            # Wait for date to terminate. Get return returncode
            p_status = p.wait()

            """ Had to remove '-' due to problems with Jinja2 variable naming,
            e.g es-qs throws error 'no es variable'
            """
            alert.update({output.replace("-", ""):str(query)[2:-3]})

        # Data Needed
        data_needed = APTutils.main_dn_calculatoin_func(cls.yaml_file)

        # if there is only 1 element in the list, print it as a string, without quotes
        if len(data_needed) == 1:
            [data_needed] = data_needed

        cls.fields.update({'data_needed':data_needed})

        tactic = []
        tactic_re = re.compile(r'attack\.\w\D+$')
        technique = []
        technique_re = re.compile(r'attack\.t\d{1,5}$')
        other_tags = []

        for tag in cls.fields.get('tags'):
            if tactic_re.match(tag):
                tactic.append(ta_mapping.get(tag))
            elif technique_re.match(tag):
                technique.append(tag.upper()[7:])
            else:
                other_tags.append(tag)

        cls.fields.update({'tactics':tactic})
        cls.fields.update({'techniques':technique})
        cls.fields.update({'other_tags':other_tags})

        triggers = []

        for trigger in technique:
            # trigger = re.search('t\d{1,5}', trigger).group(0).upper()
            path = '../triggering/atomic-red-team/atomics/' + trigger + '/' + \
                trigger + '.yaml'
            
            try:
                trigger_yaml = read_yaml_file(path)

                triggers.append(trigger)

            except FileNotFoundError:
                print(trigger  + ": No atomics trigger for this technique")
                """
                triggers.append(
                    trigger + ": No atomics trigger for this technique"
                )
                """

        cls.fields.update({'description':cls.fields.get('description').strip()}) 
        cls.fields.update({'triggers':triggers})

        cls.content = template.render(cls.fields)

        return True

    @classmethod
    def save_markdown_file(cls):
        """Write content (md template filled with data) to a file"""

        base = os.path.basename(cls.yaml_file)
        title = os.path.splitext(base)[0]

        file_path = '../Atomic_Threat_Coverage/' + cls.parent_title  +"/" + 
           title + ".md"

        # Should return True 
        return ATCutils.write_file(file_path, cls.content)


###############################################################################
############################# If exectued #####################################
###############################################################################

if __name__ == "__main__":
    """If file is executed"""

    DataNeeded("../dataneeded/DN_0001_windows_process_creation_4688.yml")
