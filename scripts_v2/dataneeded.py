#!/usr/bin/env python3

from atcutils import ATCutils

from jinja2 import Environment, FileSystemLoader

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

        
    def parse_into_fields(self, yaml_file):
        """Description"""

        # self.fields contains parsed fields obtained from yaml file
        self.fields = ATCutils.read_yaml_file(yaml_file)

        """Fill the fields with values. Put None if key not found"""
        self.title = self.fields.get("title")
        self.description = self.fields.get("description")
        self.loggingpolicy = self.fields.get("loggingpolicy")
        self.platform = self.fields.get("platform")
        self.type = self.fields.get("type")
        self.channel = self.fields.get("channel")
        self.provider = self.fields.get("provider")
        self.fields = self.fields.get("fields")
        self.sample = self.fields.get("sample")

        
    def render_markdown_template(self):
        """Description"""

        # Point to the templates directory
        env = Environment(loader=FileSystemLoader('templates'))

        # Get DataNeeded template
        template = env.get_template('markdown_dataneeded_template.md.j2')

        self.fields.update({'description':self.fields.get('description').strip()}) 

        self.content = template.render(self.fields)

        return True

        
    def save_markdown_file(self):
        """Write content (md template filled with data) to a file"""

        base = os.path.basename(self.yaml_file)
        title = os.path.splitext(base)[0]

        file_path = '../Atomic_Threat_Coverage/' + self.parent_title  + "/" + \
           title + ".md"

        return ATCutils.write_file(file_path, self.content)