#!/usr/bin/env python3

from atcutils import ATCutils

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

        
    def parse_into_fields(self, yaml_file):
        """Description"""

        # self.fields contains parsed fields obtained from yaml file
        self.fields = ATCutils.read_yaml_file(self.yaml_file)

        
    def render_markdown_template(self):
        """Description"""

        # Point to the templates directory
        env = Environment(loader=FileSystemLoader('templates'))

        # Get DataNeeded template
        template = env.get_template('markdown_loggingpolicy_template.md.j2')
        
        # get rid of newline to not mess with table in md
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

