# -*- coding: utf-8 -*-
#
# Copyright (C) 2008 Pedro Algarvio <ufs@ufsoft.org>
# Copyright (C) 2013-2015 Steffen Hoffmann <hoff.st@web.de>
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution.
#
# Author: Pedro Algarvio <ufs@ufsoft.org>

from trac.admin.api import IAdminPanelProvider
from trac.config import ListOption
from trac.core import Component, TracError, implements
from trac.notification.api import (
    IEmailDecorator, INotificationFormatter, NotificationEvent,
    NotificationSystem)
from trac.notification.mail import RecipientMatcher, set_header
from trac.util.text import exception_to_unicode
from trac.util.translation import deactivate, reactivate
from trac.web.chrome import Chrome

from acct_mgr.api import (
    IAccountChangeListener, CommonTemplateProvider, _, dgettext)
from acct_mgr.compat import genshi_template_args


class NotificationError(TracError):
    pass


class AccountChangeEvent(NotificationEvent):

    def __init__(self, category, username, data):
        super(AccountChangeEvent, self).__init__('account', category, None,
                                                 None, username)
        self.data = data


class AccountChangeListener(Component):

    implements(IAccountChangeListener)

    _notify_actions = ListOption(
        'account-manager', 'notify_actions', [],
        doc="""Comma separated list of notification actions. Available
            actions are 'new', 'change', 'delete'.
            """)

    _account_change_recipients = ListOption(
        'account-manager', 'account_changes_notify_addresses', [],
        doc="""Email addresses to notify on account created, password
            changed and account deleted.
            """)

    action_category_map = {
        'new': 'created',
        'change': 'password changed',
        'delete': 'deleted'
    }

    def __init__(self):
        self._notify_categories = []
        for action, category in self.action_category_map.iteritems():
            if action in self._notify_actions:
                self._notify_categories.append(category)

    # IAccountChangeListener methods

    def user_created(self, username, password):
        data = {'password': password}
        self._send_notification('created', username, data)

    def user_password_changed(self, username, password):
        data = {'password': password}
        self._send_notification('password changed', username, data)

    def user_deleted(self, username):
        self._send_notification('deleted', username)

    def user_password_reset(self, username, email, password):
        data = {'password': password, 'email': email}
        self._send_notification('password reset', username, data)

    def user_email_verification_requested(self, username, token):
        data = {'token': token}
        self._send_notification('verify email', username, data)

    def user_registration_approval_required(self, username):
        self._send_notification('verify email', username)

    # Helper method

    def _send_notification(self, category, username, data=None):
        event = AccountChangeEvent(category, username, data)
        subscriptions = self._subscriptions(event)
        try:
            NotificationSystem(self.env).distribute_event(event, subscriptions)
        except Exception as e:
            self.log.error("Failure sending notification for '%s' for user "
                           "%s: %s", category, username,
                           exception_to_unicode(e))
            raise NotificationError(e)

    def _subscriptions(self, event):
        matcher = RecipientMatcher(self.env)
        if event.category in ('verify email', 'password reset'):
            recipient = matcher.match_recipient(event.author)
            if recipient:
                yield recipient + ('email', 'text/plain')
        elif event.category in self._notify_categories:
            for r in self._account_change_recipients:
                recipient = matcher.match_recipient(r)
                if recipient:
                    yield recipient + ('email', 'text/plain')


class AccountNotificationFormatter(Component):

    implements(IEmailDecorator, INotificationFormatter)

    # IEmailDecorator methods

    def decorate_message(self, event, message, charset):
        if event.realm != 'account':
            return
        subject = "[%s] " % self.env.project_name
        if event.category in ('created', 'password changed', 'deleted'):
            subject += "Account %s: %s" % (event.category, event.author)
        elif event.category == 'password reset':
            subject += "Account password reset: %s" % event.author
        elif event.category == 'verify email':
            subject += "Account email verification: %s" % event.author
        set_header(message, 'Subject', subject, charset)

    # INotificationFormatter methods

    def get_supported_styles(self, transport):
        yield 'text/plain', 'account'

    def format(self, transport, style, event):
        if event.realm != 'account':
            return
        data = {
            'account': {'username': event.author},
            'login': {'link': self.env.abs_href.login()},
        }
        if event.category in ('created', 'password changed', 'deleted'):
            data['account']['action'] = event.category
            template_name = 'account_user_changes_email.txt'
        elif event.category == 'password reset':
            data['account']['password'] = event.data['password']
            template_name = 'account_reset_password_email.txt'
        elif event.category == 'verify email':
            token = event.data['token']
            data['account']['token'] = token
            data['verify'] = {
                'link': self.env.abs_href.verify_email(token=token, verify=1)
            }
            template_name = 'account_verify_email.txt'
        return self._format_body(data, template_name)

    # Internal methods

    def _format_body(self, data, template_name):
        # 3 commented lines are replacements for when Trac < 1.4 is dropped
        chrome = Chrome(self.env)
        data = chrome.populate_data(None, data)
        template = chrome.load_template(template_name, method='text')
        #template = chrome.load_template(template_name, text=True)
        t = deactivate()  # don't translate the e-mail stream
        try:
            stream = template.generate(**data)
            return stream.render('text', encoding='utf-8')
            #body = chrome.render_template_string(template, data, text=True)
            #return body.encode('utf-8')
        except Exception as e:
            self.log.error("Failed to format body of notification mail: %s",
                           exception_to_unicode(e, traceback=True))
        finally:
            reactivate(t)


class AccountChangeNotificationAdminPanel(CommonTemplateProvider):
    implements(IAdminPanelProvider)

    # IAdminPageProvider methods

    def get_admin_panels(self, req):
        if 'ACCTMGR_CONFIG_ADMIN' in req.perm:
            yield ('accounts', _("Accounts"), 'notification',
                   _("Notification"))

    def render_admin_panel(self, req, cat, page, path_info):
        if page == 'notification':
            return self._do_config(req)

    def _do_config(self, req):
        cfg = self.config['account-manager']
        if req.method == 'POST':
            cfg.set('account_changes_notify_addresses',
                    ' '.join(req.args.getlist('notify_addresses')))
            cfg.set('notify_actions',
                    ','.join(req.args.getlist('notify_actions')))
            self.config.save()
            req.redirect(req.href.admin('accounts', 'notification'))

        notify_addresses = cfg.getlist('account_changes_notify_addresses',
                                       sep=' ')
        notify_actions = cfg.getlist('notify_actions')
        data = {
            '_dgettext': dgettext,
            'notify_actions': notify_actions,
            'notify_addresses': notify_addresses
        }
        return genshi_template_args(self.env, 'account_notification.html',
                                    data)
