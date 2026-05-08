from __future__ import annotations

import email.policy
import time
from email.message import EmailMessage
from email.utils import formatdate
from typing import Any, Dict, List, Optional


def looks_like_rfc822(body: str) -> bool:
    return '\nSubject:' in body[:500] or body.startswith('Subject:') or '\nFrom:' in body[:500]


def format_addr(addr: Optional[Dict[str, Any]]) -> str:
    if not addr:
        return ''
    name = addr.get('Name') or ''
    address = addr.get('Address') or ''
    return f'{name} <{address}>' if name else address


def format_addr_list(addrs: List[Dict[str, Any]]) -> str:
    return ', '.join(filter(None, (format_addr(addr) for addr in addrs)))


def proton_message_to_rfc822(message: Dict[str, Any], body: str) -> bytes:
    if looks_like_rfc822(body):
        return body.encode()

    eml = EmailMessage()
    headers = message.get('ParsedHeaders') or {}
    eml['Subject'] = message.get('Subject') or headers.get('Subject', '')
    from_header = headers.get('From') or format_addr(message.get('Sender'))
    if from_header:
        eml['From'] = from_header
    to_header = headers.get('To') or format_addr_list(message.get('ToList', []))
    if to_header:
        eml['To'] = to_header
    date_header = headers.get('Date') or formatdate(message.get('Time', int(time.time())), localtime=False)
    eml['Date'] = date_header
    message_id = headers.get('Message-Id') or headers.get('Message-ID') or message.get('ExternalID') or message.get('ID')
    if message_id:
        if not str(message_id).startswith('<'):
            message_id = f'<{message_id}>'
        eml['Message-ID'] = message_id
    mime_type = message.get('MIMEType') or headers.get('Content-Type') or 'text/plain'
    if 'html' in mime_type.lower():
        eml.set_content('')
        eml.add_alternative(body, subtype='html')
    else:
        eml.set_content(body)
    return eml.as_bytes(policy=email.policy.SMTP)
