#!/usr/bin/env python3

# Import ATC classes
from dataneeded import DataNeeded
from detectionrule import DetectionRule
# from enrichments import Enrichments
from loggingpolicy import LoggingPolicy

# Import ATC Utils
from atcutils import ATCutils

# Others
import glob
import traceback
import sys


class PopulateMarkdown:
    """Class for populating markdown repo"""

    def __init__(self, lp=False, dn=False, dr=False, en=False, tg=False,
                 auto=False, art_dir=False, atc_dir=False, lp_path=False,
                 dn_path=False, dr_path=False, en_path=False):
        """Init"""

        # Check if atc_dir provided
        if atc_dir:
            self.atc_dir = atc_dir

        else:
            self.atc_dir = '../Atomic_Threat_Coverage/'

        # Check if art_dir provided
        if art_dir:
            self.art_dir = art_dir

        else:
            self.art_dir = '../triggering/atomic-red-team/'

        # Main logic
        if auto:
            self.logging_policy(lp_path)
            self.data_needed(dn_path)
            self.triggering()
            self.detection_rule(dr_path)

        if lp:
            self.logging_policy(lp_path)

        if dn:
            self.data_needed(dn_path)

        if dr:
            self.detection_rule(dr_path)

        if en:
            self.enrichment(en_path)

        if tg:
            self.triggering()

    def triggering(self):
        """Populate triggering"""

        if self.art_dir and self.atc_dir:
            r = ATCutils.populate_tg_markdown(art_dir=self.art_dir,
                                              atc_dir=self.atc_dir)

        elif self.art_dir:
            r = ATCutils.populate_tg_markdown(art_dir=self.art_dir)

        elif self.atc_dir:
            r = ATCutils.populate_tg_markdown(atc_dir=self.atc_dir)

        else:
            r = ATCutils.populate_tg_markdown()

        return r

    def logging_policy(self, lp_path):
        """Desc"""

        if lp_path:
            lp_list = glob.glob(lp_path + '*.yml')
        else:
            lp_list = glob.glob('../loggingpolicies/*.yml')

        for lp_file in lp_list:
            try:
                lp = LoggingPolicy(lp_file)
                lp.render_template("markdown")
                lp.save_markdown_file(atc_dir=self.atc_dir)
            except Exception as e:
                print(lp_file + " failed\n\n%s\n\n" % e)

    def data_needed(self, dn_path):
        """Desc"""

        if dn_path:
            dn_list = glob.glob(dn_path + '*.yml')
        else:
            dn_list = glob.glob('../dataneeded/*.yml')

        for dn_file in dn_list:
            try:
                dn = DataNeeded(dn_file)
                dn.render_template("markdown")
                dn.save_markdown_file(atc_dir=self.atc_dir)
            except Exception as e:
                print(dn_file + " failed\n\n%s\n\n" % e)

    def detection_rule(self, dr_path):
        """Desc"""

        if dr_path:
            dr_list = glob.glob(dr_path + '*.yml')
        else:
            dr_list = glob.glob('../detectionrules/*.yml')

        for dr_file in dr_list:
            try:
                dr = DetectionRule(dr_file)
                dr.render_template("markdown")
                dr.save_markdown_file(atc_dir=self.atc_dir)
            except Exception as e:
                print(dr_file + " failed\n\n%s\n\n" % e)
                exc_type, exc_value, exc_traceback = sys.exc_info()
                print("*** print_tb:")
                traceback.print_tb(exc_traceback, limit=1, file=sys.stdout)
                print("*** print_exception:")
                # exc_type below is ignored on 3.5 and later
                traceback.print_exception(exc_type, exc_value, exc_traceback,
                                          limit=2, file=sys.stdout)

    def enrichment(self, en_path):
        """Nothing here yet"""

        pass
