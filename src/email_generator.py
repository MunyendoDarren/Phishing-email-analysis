"""
Sample Email Generator
-----------------------
Generates a handful of synthetic .eml files (standard email format) into
data/samples/ — a mix of phishing attempts and legitimate emails — so
the analyzer has realistic input to run against out of the box.

These are entirely fabricated for demonstration purposes: fictional
senders, fake links, no real accounts, brands, or people are targeted
or contacted. Nothing here is sent anywhere.

Usage:
    python email_generator.py
"""

import os
from email.message import EmailMessage
from email.utils import formatdate

OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "data", "samples")


def build_email(subject, from_header, to_header, reply_to, body_text, body_html=None,
                 extra_headers=None, filename=None):
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = from_header
    msg["To"] = to_header
    msg["Date"] = formatdate(localtime=True)
    if reply_to:
        msg["Reply-To"] = reply_to
    if extra_headers:
        for key, value in extra_headers.items():
            msg[key] = value

    msg.set_content(body_text)
    if body_html:
        msg.add_alternative(body_html, subtype="html")

    path = os.path.join(OUTPUT_DIR, filename)
    with open(path, "wb") as f:
        f.write(bytes(msg))
    return path


def generate_samples():
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    generated = []

    # --- Sample 1: Classic account-verification phishing (lookalike domain) ---
    body_text = (
        "Dear Customer,\n\n"
        "We detected unusual activity on your account. Your account will be "
        "suspended in 24 hours unless you verify your identity immediately.\n\n"
        "Click here to verify now: http://paypa1-secure-verify.com/login\n\n"
        "Failure to act within 24 hours will result in permanent suspension.\n\n"
        "PayPal Security Team"
    )
    body_html = (
        '<p>Dear Customer,</p>'
        '<p>We detected unusual activity on your account. Your account will be '
        'suspended in <b>24 hours</b> unless you verify your identity immediately.</p>'
        '<p><a href="http://paypa1-secure-verify.com/login">Click here to verify your account</a></p>'
        '<p>Failure to act within 24 hours will result in permanent suspension.</p>'
        '<p>PayPal Security Team</p>'
    )
    generated.append(build_email(
        subject="Urgent: Your Account Has Been Limited",
        from_header='"PayPal Security" <security@paypa1-secure-verify.com>',
        to_header="user@example.com",
        reply_to="noreply@paypa1-secure-verify.com",
        body_text=body_text,
        body_html=body_html,
        filename="phishing_account_verification.eml",
    ))

    # --- Sample 2: Fake IT helpdesk / credential harvest, free-mail sender ---
    body_text = (
        "Hello,\n\n"
        "Our records show your mailbox is almost full and will stop receiving "
        "new emails. To avoid interruption, please confirm your credentials "
        "within 12 hours using the link below.\n\n"
        "http://bit.ly/mailbox-quota-fix\n\n"
        "IT Support Desk"
    )
    generated.append(build_email(
        subject="ACTION REQUIRED: Mailbox Quota Exceeded",
        from_header='"IT Support Desk" <it-support@gmail.com>',
        to_header="user@example.com",
        reply_to="it.helpdesk.verify@gmail.com",
        body_text=body_text,
        extra_headers={"X-Priority": "1"},
        filename="phishing_it_helpdesk.eml",
    ))

    # --- Sample 3: Fake invoice with suspicious attachment reference + IP-based link ---
    body_text = (
        "Dear Sir/Madam,\n\n"
        "Please find attached invoice #88213 for immediate payment. "
        "Kindly review and process payment today to avoid late fees.\n\n"
        "View invoice: http://185.220.101.47/invoice/view?id=88213\n\n"
        "Accounts Receivable"
    )
    generated.append(build_email(
        subject="Overdue Invoice #88213 - Payment Required Today",
        from_header='"Accounts Receivable" <billing@globalsupply-invoices.net>',
        to_header="finance@example.com",
        reply_to=None,
        body_text=body_text,
        filename="phishing_fake_invoice.eml",
    ))

    # --- Sample 4: Legitimate-looking newsletter (control example) ---
    body_text = (
        "Hi there,\n\n"
        "Here's your monthly newsletter with product updates and tips.\n\n"
        "Read the full update on our blog: https://blog.example.com/august-update\n\n"
        "Thanks for being a subscriber!\n\n"
        "The Example Corp Team"
    )
    generated.append(build_email(
        subject="Your August Product Update from Example Corp",
        from_header='"Example Corp Newsletter" <newsletter@example.com>',
        to_header="user@example.com",
        reply_to="support@example.com",
        body_text=body_text,
        extra_headers={
            "Authentication-Results": "mx.example.com; spf=pass smtp.mailfrom=example.com; "
                                       "dkim=pass header.d=example.com; dmarc=pass",
        },
        filename="legitimate_newsletter.eml",
    ))

    # --- Sample 5: Legitimate internal work email (control example) ---
    body_text = (
        "Hi team,\n\n"
        "Quick reminder that the sprint review is moved to 3pm tomorrow in "
        "the usual meeting room. Agenda and slides are in the shared drive "
        "if you'd like to review beforehand.\n\n"
        "See you there,\nDarren"
    )
    generated.append(build_email(
        subject="Sprint Review Moved to 3pm Tomorrow",
        from_header='"Darren Otieno" <darren@example.com>',
        to_header="team@example.com",
        reply_to=None,
        body_text=body_text,
        extra_headers={
            "Authentication-Results": "mx.example.com; spf=pass smtp.mailfrom=example.com; "
                                       "dkim=pass header.d=example.com; dmarc=pass",
        },
        filename="legitimate_internal.eml",
    ))

    return generated


def main():
    paths = generate_samples()
    print(f"Generated {len(paths)} sample .eml files in {OUTPUT_DIR}:\n")
    for path in paths:
        print(f"  - {os.path.basename(path)}")


if __name__ == "__main__":
    main()
