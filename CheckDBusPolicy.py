# vim:sw=4:et
#############################################################################
# File          : CheckDBusPolicy.py
# Package       : rpmlint
# Author        : Ludwig Nussel
# Purpose       : Check for broken DBus policies
#############################################################################

# causes extraction of package if it contains files in /etc/dbus-1/system.d/

from Filter import *
import AbstractCheck
from xml.dom.minidom import parse

class DBusPolicyCheck(AbstractCheck.AbstractCheck):
    def __init__(self):
        AbstractCheck.AbstractCheck.__init__(self, "CheckDBusPolicy")

    def check(self, pkg):

        if pkg.isSource():
            return

        files = pkg.files()

        for f in files:
            if f in pkg.ghostFiles():
                continue

            # catch xml exceptions 
            try:
                if f.startswith("/etc/dbus-1/system.d/"):
                    send_policy_seen = False
                    lf = pkg.dirName() + f
                    xml = parse(lf)
                    for p in xml.getElementsByTagName("policy"):
                        for allow in p.getElementsByTagName("allow"):
                            if ( allow.hasAttribute('send_interface') \
                                    or allow.hasAttribute('send_member') \
                                    or allow.hasAttribute('send_path')) \
                                and not allow.hasAttribute('send_destination'):
                                    send_policy_seen = True
                                    printError(pkg, 'dbus-policy-allow-without-destination', "%(file)s: %(xml)s" % { 'file':f, 'xml':allow.toxml() })
                            elif allow.hasAttribute('send_destination'):
                                    send_policy_seen = True

                            if allow.hasAttribute('receive_sender') \
                                or allow.hasAttribute('receive_interface'):
                                    printInfo(pkg, 'dbus-policy-allow-receive', "%(file)s: %(xml)s" % { 'file':f, 'xml':allow.toxml() })

                        for deny in p.getElementsByTagName("deny"):
                            if ( deny.hasAttribute('send_interface') \
                                and not deny.hasAttribute('send_destination')):
                                    printError(pkg, 'dbus-policy-deny-without-destination', "%(file)s: %(xml)s" % { 'file':f, 'xml':deny.toxml() })
        
                    if not send_policy_seen:
                        printError(pkg, 'dbus-policy-missing-allow', "%(file)s does not allow communication" % { 'file':f })

            except Exception, x:
                printError(pkg, 'rpmlint-exception', "%(file)s raised an exception: %(x)s" % {'file':f, 'x':x})
                continue

check=DBusPolicyCheck()

if Config.info:
    addDetails(
'dbus-policy-allow-without-destination',
"""'allow' directives must always specify a 'send_destination'""",
'dbus-policy-allow-receive',
"""allow receive_* is normally not needed as that is the default""",
'dbus-policy-deny-without-destination',
"""'deny' directives must always specify a 'send_destination' otherwise messages to other services could be blocked""",
'dbus-policy-missing-allow',
"""every dbus config normally needs a line of the form
<allow send_destination="org.foo.bar"/>
or similar. If that is missing the service will not work with a dbus that uses
deny as default policy""",
'rpmlint-exception',
"""A python exception was raised which prevents further analysis""",
)
