# -*- coding: utf-8 -*-
#
# Copyright (C) 2010 Chris Shenton <chris@koansys.com>
# Copyright (C) 2015 Steffen Hoffmann <hoff.st@web.de>
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution.
#
# Author: Chris Shenton <chris@koansys.com>

from StringIO import StringIO

from acct_mgr.api import IPasswordStore
from trac.config import IntOption, Option
from trac.core import Component, implements
from trac.util.text import unicode_passwd

DICTIONARY = u"""
ATTRIBUTE User-Name     1 string
ATTRIBUTE User-Password 2 string encrypt=1
"""


class RadiusAuthStore(Component):
    """[extra] Provides RADIUS authentication support.

    Custom configuration is mandatory.

    Provide IP address and authentication port of your RADIUS server. RADIUS
    uses UDP port 1812 for authentication as per IETF RFC2865, but old servers
    may still use 1645. You must also supply a shared secret, which the RADIUS
    server admin must disclose to you.
    """

    implements(IPasswordStore)

    radius_server = Option('account-manager', 'radius_server',
        doc="RADIUS server IP address, required.")

    radius_authport = IntOption('account-manager', 'radius_authport', 1812,
        doc="RADIUS server authentication port, defaults to 1812.")

    # Conceal shared secret.
    radius_secret = unicode_passwd(Option('account-manager', 'radius_secret',
        doc="RADIUS server shared secret, required."))

    def get_users(self):
        """Returns an iterable of the known usernames."""
        return []

    def has_user(self, user):
        """Returns whether the user account exists."""
        # DEVEL: Shall we really deny knowing a specified user?
        return False

    def check_password(self, username, password):
        """Checks if the password is valid for the user."""
        # Handle pyrad lib absence and upstream incompatibilities gracefully.
        try:
            import pyrad.packet
            from pyrad.client import Client, Timeout
            from pyrad.dictionary import Dictionary
        except ImportError, e:
            self.log.error("RADIUS auth store could not import pyrad, "
                           "need to install the egg: %s", e)
            return

        self.log.debug("RADIUS server=%s:%s (authport), secret='%s'",
                       self.radius_server, self.radius_authport,
                       self.radius_secret)
        self.log.debug("RADIUS auth callenge for username=%s password=%s",
                       username, unicode_passwd(password))

        client = Client(server=self.radius_server,
                        authport=self.radius_authport,
                        secret=self.radius_secret.encode('utf-8'),
                        dict=Dictionary(StringIO(DICTIONARY)),
                        )

        req = client.CreateAuthPacket(code=pyrad.packet.AccessRequest,
                                      User_Name=username.encode('utf-8'))
        req['User-Password'] = req.PwCrypt(password)

        self.log.debug("RADIUS auth sending packet req=%s", req)
        try:
            reply = client.SendPacket(req)
        except Timeout, e:
            self.log.error("RADIUS timeout contacting server=%s:%s (%s)",
                           self.radius_server, self.radius_authport, e)
            return
        # DEVEL: Too broad, narrow down that exception handler scope.
        except Exception, e:
            self.log.error("RADIUS error while using server=%s:%s: (%s)",
                           self.radius_server, self.radius_authport, e)
            return
        self.log.debug("RADIUS authentication reply code=%s", reply.code)

        if pyrad.packet.AccessAccept == reply.code:
            self.log.debug("RADIUS Accept for username=%s", username)
            return True
        # Rejection of login attempt, stopping further auth store interation.
        elif pyrad.packet.AccessReject == reply.code:
            self.log.debug("RADIUS Reject for username=%s", username)
            return False
        # DEVEL: Any way to alert users that RSA token is in 'Next Token' mode
        #        so they know to fix it?
        elif pyrad.packet.AccessChallenge == reply.code:
            self.log.info("RADIUS returned Challenge for username=%s; "
                          "on RSA servers this indicates 'Next Token' mode.",
                          username)
            return
        else:
            self.log.warning("RADIUS Unknown reply code (%s) for username=%s",
                             reply.code, username)
        return
