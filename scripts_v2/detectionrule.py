#!/usr/bin/env python3

from atcutils import ATCutils

from jinja2 import Environment, FileSystemLoader

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

        
    def parse_into_fields(self):
        """Description"""

        # self.fields contains parsed fields obtained from yaml file
        self.fields = ATCutils.read_yaml_file(self.yaml_file)

        
    def render_markdown_template(self):
        """Render template with data in it"""

        # Point to the templates directory
        env = Environment(loader=FileSystemLoader('templates'))

        # Get DetectionRule template
        template = env.get_template('markdown_alert_template.md.j2')

        # Read raw sigma rule
        sigma_rule = ATCutils.read_rule_file(self.yaml_file)

        # Put raw sigma rule into fields var
        self.fields.update({'sigma_rule':sigma_rule})

        # Define which queries we want from Sigma
        queries = ["es-qs", "xpack-watcher", "graylog"]

        # Convert sigma rule into queries (for instance, graylog query)
        for query in queries:
            # prepare command to execute from shell
            cmd = "../detectionrules/sigma/tools/sigmac -t " + \
                output + " --ignore-backend-errors " + self.yaml_file

            p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)

            (query, err) = p.communicate()

            # Wait for date to terminate. Get return returncode
            p_status = p.wait()

            """ Had to remove '-' due to problems with Jinja2 variable naming,
            e.g es-qs throws error 'no es variable'
            """
            alert.update({output.replace("-", ""):str(query)[2:-3]})

        # Data Needed
        data_needed = APTutils.main_dn_calculatoin_func(self.yaml_file)

        # if there is only 1 element in the list, print it as a string, without quotes
        if len(data_needed) == 1:
            [data_needed] = data_needed

        self.fields.update({'data_needed':data_needed})

        tactic = []
        tactic_re = re.compile(r'attack\.\w\D+$')
        technique = []
        technique_re = re.compile(r'attack\.t\d{1,5}$')
        other_tags = []

        for tag in self.fields.get('tags'):
            if tactic_re.match(tag):
                tactic.append(ta_mapping.get(tag))
            elif technique_re.match(tag):
                technique.append(tag.upper()[7:])
            else:
                other_tags.append(tag)

        self.fields.update({'tactics':tactic})
        self.fields.update({'techniques':technique})
        self.fields.update({'other_tags':other_tags})

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

        self.fields.update({'description':self.fields.get('description').strip()}) 
        self.fields.update({'triggers':triggers})

        self.content = template.render(self.fields)

        return True

        
    def save_markdown_file(self):
        """Write content (md template filled with data) to a file"""

        base = os.path.basename(self.yaml_file)
        title = os.path.splitext(base)[0]

        file_path = '../Atomic_Threat_Coverage/' + self.parent_title  + "/" + \
           title + ".md"

        # Should return True 
        return ATCutils.write_file(file_path, self.content)
