#!/usr/bin/env python3

from atcutils import ATCutils

from jinja2 import Environment, FileSystemLoader

import os

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

        
    def parse_into_fields(self, yaml_file):
        """Description"""

        self.enrichments_parsed_file = ATCutils.read_yaml_file(yaml_file)

        
    def render_markdown_template(self):
        """Description"""
        
        pass

        
    def save_markdown_file(self):
        """Write content (md template filled with data) to a file"""

        base = os.path.basename(self.yaml_file)
        title = os.path.splitext(base)[0]

        file_path = '../Atomic_Threat_Coverage/' + self.parent_title  + "/" + \
           title + ".md"

        return ATCutils.write_file(file_path, self.content)

