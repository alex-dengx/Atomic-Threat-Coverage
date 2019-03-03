from atcutils import ATCutils


class ATCEntity:
    ATCconfig = ATCutils.read_yaml_file("config.yml")

    def __init__(self):
        pass


    def parse_into_fields(self, yaml_file):
        """Description"""

        self.fields = ATCutils.read_yaml_file(yaml_file)