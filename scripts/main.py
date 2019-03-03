#!/usr/bin/env python3

from populatemarkdown import PopulateMarkdown
from populateconfluence import PopulateConfluence
from thehive_templates import RPTheHive
from atcutils import ATCutils

# For confluence
from requests.auth import HTTPBasicAuth

# Others
import argparse
import getpass

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Main function of ATC. ' +
                                     'This function is handling generating' +
                                     'markdown files and/or ' +
                                     'populating confluence')

    # Mutually exclusive group for chosing the output of the script
    group = parser.add_mutually_exclusive_group(required=True)

    group.add_argument('-C', '--confluence', action='store_true',
                       help='Set the output to be a Confluence')
    group.add_argument('-M', '--markdown', action='store_true',
                       help='Set the output to be markdown files')
    group.add_argument('-T', '--thehive', action='store_true',
                       help='Generate TheHive Case templates')

    # Mutually exclusive group for chosing type of data
    group2 = parser.add_mutually_exclusive_group(required=False)

    group2.add_argument('-A', '--auto', action='store_true',
                        help='Build full repository')
    group2.add_argument('-LP', '--loggingpolicy', action='store_true',
                        help='Build logging policy part')
    group2.add_argument('-DN', '--dataneeded', action='store_true',
                        help='Build data needed part')
    group2.add_argument('-DR', '--detectionrule', action='store_true',
                        help='Build detection rule part')
    group2.add_argument('-EN', '--enrichment', action='store_true',
                        help='Build enrichment part')
    group2.add_argument('-TG', '--triggers', action='store_true',
                        help='Build triggers part')
    group2.add_argument('-RA', '--responseactions', action='store_true',
                        help='Build response action part')
    group2.add_argument('-RP', '--responseplaybook', action='store_true',
                        help='Build response playbook part')

    # Init capabilities
    parser.add_argument('-i', '--init', action='store_true',
                        help="Build initial pages or directories " +
                        "depending on the export type")
    args = parser.parse_args()

    if args.markdown:
        PopulateMarkdown(auto=args.auto, lp=args.loggingpolicy,
                         dn=args.dataneeded, dr=args.detectionrule,
                         tg=args.triggers, en=args.enrichment,
                         ra=args.responseactions, rp=args.responseplaybook,
                         init=args.init)

    elif args.confluence:
        print("Provide confluence credentials\n")

        mail = input("Login: ")
        password = getpass.getpass(prompt='Password: ', stream=None)

        auth = HTTPBasicAuth(mail, password)

        PopulateConfluence(auth=auth, auto=args.auto, lp=args.loggingpolicy,
                           dn=args.dataneeded, dr=args.detectionrule,
                           tg=args.triggers, en=args.enrichment,
                           ra=args.responseactions, rp=args.responseplaybook,
                           init=args.init)
    elif args.thehive:
        ATCconfig = ATCutils.read_yaml_file("config.yml")
        print("HINT: Make sure proper directories are " +
              "configured in the config.yml")
        if ATCconfig.get('response_playbooks_dir') and \
                ATCconfig.get('response_actions_dir') and \
                ATCconfig.get('thehive_templates_dir'):
            RPTheHive(
                inputRP=ATCconfig.get('response_playbooks_dir'),
                inputRA=ATCconfig.get('response_actions_dir'),
                output=ATCconfig.get('thehive_templates_dir')
            )
        else:
            print("ERROR: Dirs were not provided in the config.yml")
