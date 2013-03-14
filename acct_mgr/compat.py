# -*- coding: utf-8 -*-
#
# Copyright (C) 2005 Matthew Good <trac@matt-good.net>
# Copyright (C) 2010-2013 Steffen Hoffmann <hoff.st@web.de>
# Copyright (C) 2011 Edgewall Software
# All rights reserved.
#
# This software is licensed as described in the file COPYING, which
# you should have received as part of this distribution.
#
# Author: Matthew Good <trac@matt-good.net>

from genshi.builder import tag
from tokenize import generate_tokens, COMMENT, NAME, OP, STRING

from trac.util.datefmt import format_datetime, pretty_timedelta
from trac.util.text import to_unicode
from trac.web.chrome import Chrome


try:
    from trac.util import as_int
# Provide the function for compatibility (available since Trac 0.12).
except ImportError:
    def as_int(s, default, min=None, max=None):
        """Convert s to an int and limit it to the given range, or
        return default if unsuccessful (copied verbatim from Trac0.12dev).
        """
        try:
            value = int(s)
        except (TypeError, ValueError):
            return default
        if min is not None and value < min:
            value = min
        if max is not None and value > max:
            value = max
        return value

# inspect.cleandoc() was introduced in Python 2.6, and this compatibility
# code replicates source in trac.util.compat 
try:
    from inspect import cleandoc
except ImportError:
    import sys

    # Taken from Python 2.6
    def cleandoc(doc):
        """De-indent a multi-line text.
    
        Any whitespace that can be uniformly removed from the second line
        onwards is removed."""
        try:
            lines = doc.expandtabs().split('\n')
        except UnicodeError:
            return None
        else:
            # Find minimum indentation of any non-blank lines after first line
            margin = sys.maxint
            for line in lines[1:]:
                content = len(line.lstrip())
                if content:
                    indent = len(line) - content
                    margin = min(margin, indent)
            # Remove indentation
            if lines:
                lines[0] = lines[0].lstrip()
            if margin < sys.maxint:
                for i in range(1, len(lines)):
                    lines[i] = lines[i][margin:]
            # Remove any trailing or leading blank lines
            while lines and not lines[-1]:
                lines.pop()
            while lines and not lines[0]:
                lines.pop(0)
            return '\n'.join(lines)

# Provide the function for compatibility (available since Trac 1.0).
try:
    from babel.messages.extract import extract_javascript
    from babel.messages.frontend import extract_messages, init_catalog, \
                                        compile_catalog, update_catalog
    from babel.util import parse_encoding
    from babel.support import Translations

    # Do not care about option docs translation (for Trac < 1.0).
    _DEFAULT_KWARGS_MAPS = dict()

    _DEFAULT_CLEANDOC_KEYWORDS = ('cleandoc_',)

    def extract_python(fileobj, keywords, comment_tags, options):
        """Extract messages from Python source code, This is patched
        extract_python from Babel to support keyword argument mapping.

        `kwargs_maps` option: names of keyword arguments will be mapping to
        index of messages array.

        `cleandoc_keywords` option: a list of keywords to clean up the
        extracted messages with `cleandoc`.
        """
        funcname = lineno = message_lineno = None
        kwargs_maps = func_kwargs_map = None
        call_stack = -1
        buf = []
        messages = []
        messages_kwargs = {}
        translator_comments = []
        in_def = in_translator_comments = False
        comment_tag = None

        encoding = parse_encoding(fileobj) \
                   or options.get('encoding', 'iso-8859-1')
        kwargs_maps = _DEFAULT_KWARGS_MAPS.copy()
        if 'kwargs_maps' in options:
            kwargs_maps.update(options['kwargs_maps'])
        cleandoc_keywords = set(_DEFAULT_CLEANDOC_KEYWORDS)
        if 'cleandoc_keywords' in options:
            cleandoc_keywords.update(options['cleandoc_keywords'])

        tokens = generate_tokens(fileobj.readline)
        tok = value = None
        for _ in tokens:
            prev_tok, prev_value = tok, value
            tok, value, (lineno, _), _, _ = _
            if call_stack == -1 and tok == NAME and value in ('def', 'class'):
                in_def = True
            elif tok == OP and value == '(':
                if in_def:
                    # Avoid false positives for declarations such as:
                    # def gettext(arg='message'):
                    in_def = False
                    continue
                if funcname:
                    message_lineno = lineno
                    call_stack += 1
                kwarg_name = None
            elif in_def and tok == OP and value == ':':
                # End of a class definition without parens
                in_def = False
                continue
            elif call_stack == -1 and tok == COMMENT:
                # Strip the comment token from the line
                value = value.decode(encoding)[1:].strip()
                if in_translator_comments and \
                        translator_comments[-1][0] == lineno - 1:
                    # We're already inside a translator comment, continue
                    # appending
                    translator_comments.append((lineno, value))
                    continue
                # If execution reaches this point, let's see if comment line
                # starts with one of the comment tags
                for comment_tag in comment_tags:
                    if value.startswith(comment_tag):
                        in_translator_comments = True
                        translator_comments.append((lineno, value))
                        break
            elif funcname and call_stack == 0:
                if tok == OP and value == ')':
                    if buf:
                        message = ''.join(buf)
                        if kwarg_name in func_kwargs_map:
                            messages_kwargs[kwarg_name] = message
                        else:
                            messages.append(message)
                        del buf[:]
                    else:
                        messages.append(None)

                    for name, message in messages_kwargs.iteritems():
                        if name not in func_kwargs_map:
                            continue
                        index = func_kwargs_map[name]
                        while index >= len(messages):
                            messages.append(None)
                        messages[index - 1] = message

                    if funcname in cleandoc_keywords:
                        messages = [m and cleandoc(m) for m in messages]
                    if len(messages) > 1:
                        messages = tuple(messages)
                    else:
                        messages = messages[0]
                    # Comments don't apply unless they immediately preceed the
                    # message
                    if translator_comments and \
                            translator_comments[-1][0] < message_lineno - 1:
                        translator_comments = []

                    yield (message_lineno, funcname, messages,
                           [comment[1] for comment in translator_comments])

                    funcname = lineno = message_lineno = None
                    kwarg_name = func_kwargs_map = None
                    call_stack = -1
                    messages = []
                    messages_kwargs = {}
                    translator_comments = []
                    in_translator_comments = False
                elif tok == STRING:
                    # Unwrap quotes in a safe manner, maintaining the string's
                    # encoding
                    # https://sourceforge.net/tracker/?func=detail&atid=355470&
                    # aid=617979&group_id=5470
                    value = eval('# coding=%s\n%s' % (encoding, value),
                                 {'__builtins__':{}}, {})
                    if isinstance(value, str):
                        value = value.decode(encoding)
                    buf.append(value)
                elif tok == OP and value == '=' and prev_tok == NAME:
                    kwarg_name = prev_value
                elif tok == OP and value == ',':
                    if buf:
                        message = ''.join(buf)
                        if kwarg_name in func_kwargs_map:
                            messages_kwargs[kwarg_name] = message
                        else:
                            messages.append(message)
                        del buf[:]
                    else:
                        messages.append(None)
                    kwarg_name = None
                    if translator_comments:
                        # We have translator comments, and since we're on a
                        # comma(,) user is allowed to break into a new line
                        # Let's increase the last comment's lineno in order
                        # for the comment to still be a valid one
                        old_lineno, old_comment = translator_comments.pop()
                        translator_comments.append((old_lineno+1, old_comment))
            elif call_stack > 0 and tok == OP and value == ')':
                call_stack -= 1
            elif funcname and call_stack == -1:
                funcname = func_kwargs_map = kwarg_name = None
            elif tok == NAME and value in keywords:
                funcname = value
                func_kwargs_map = kwargs_maps.get(funcname, {})
                kwarg_name = None
except:
    pass

try:
    from trac.util.text import exception_to_unicode
# Provide the function for compatibility (available since Trac 0.11.3).
except:
    def exception_to_unicode(e, traceback=False):
        """Convert an `Exception` to an `unicode` object.

        In addition to `to_unicode`, this representation of the exception
        also contains the class name and optionally the traceback.
        This replicates the Trac core function for backwards-compatibility.
        """
        message = '%s: %s' % (e.__class__.__name__, to_unicode(e))
        if traceback:
            from trac.util import get_last_traceback
            traceback_only = get_last_traceback().split('\n')[:-2]
            message = '\n%s\n%s' % (to_unicode('\n'.join(traceback_only)),
                                    message)
        return message

# Compatibility code for `pretty_dateinfo` from template data dict
# (available since Trac 1.0)
def get_pretty_dateinfo(env, req):
    """Return the function defined in trac.web.chrome.Chrome.populate_data .

    For Trac 0.11 and 0.12 it still provides a slightly simplified version.
    """
    # Function is not a class attribute, must be extracted from data dict.
    fn = Chrome(env).populate_data(req, {}).get('pretty_dateinfo')
    if not fn:
        from acct_mgr.api import _
        def _pretty_dateinfo(date, format=None, dateonly=False):
            absolute = format_datetime(date, tzinfo=req.tz)
            relative = pretty_timedelta(date)
            if format == 'absolute':
                label = absolute
                # TRANSLATOR: Sync with same msgid in Trac 0.13, please.
                title = _("%(relativetime)s ago", relativetime=relative)
            else:
                if dateonly:
                    label = relative
                else:
                    label = _("%(relativetime)s ago", relativetime=relative)
                title = absolute
            return tag.span(label, title=title)
    return fn and fn or _pretty_dateinfo

# Compatibility code for `ComponentManager.is_enabled`
# (available since Trac 0.12)
def is_enabled(env, cls):
    """Return whether the given component class is enabled.

    For Trac 0.11 the missing algorithm is included as fallback.
    """
    try:
        return env.is_enabled(cls)
    except AttributeError:
        if cls not in env.enabled:
            env.enabled[cls] = env.is_component_enabled(cls)
        return env.enabled[cls]
