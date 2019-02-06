from atcutils import ATCutils
from pprint import pprint
nazwa = "apt_hurricane_panda"
_ = ATCutils.main_dn_calculatoin_func("../detectionrules/%s.yml" % nazwa)

pprint(_)
