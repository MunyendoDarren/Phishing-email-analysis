# Sample Output

Real output from running the analyzer against all 5 generated sample
emails (3 phishing, 2 legitimate).

```
$ python3 src/email_generator.py
Generated 5 sample .eml files in data/samples:

  - phishing_account_verification.eml
  - phishing_it_helpdesk.eml
  - phishing_fake_invoice.eml
  - legitimate_newsletter.eml
  - legitimate_internal.eml
```

```
$ python3 src/analyzer.py data/samples/

======================================================================
 File:    legitimate_internal.eml
 Subject: Sprint Review Moved to 3pm Tomorrow
 From:    Darren Otieno <darren@example.com>
 Score:   0 / 100
 Verdict: No Indicators Found
----------------------------------------------------------------------
 No phishing indicators detected.
======================================================================

======================================================================
 File:    legitimate_newsletter.eml
 Subject: Your August Product Update from Example Corp
 From:    Example Corp Newsletter <newsletter@example.com>
 Score:   0 / 100
 Verdict: No Indicators Found
----------------------------------------------------------------------
 No phishing indicators detected.
======================================================================

======================================================================
 File:    phishing_account_verification.eml
 Subject: Urgent: Your Account Has Been Limited
 From:    PayPal Security <security@paypa1-secure-verify.com>
 Score:   100 / 100
 Verdict: Likely Phishing
----------------------------------------------------------------------
 [MEDIUM] (header) No Authentication-Results header present — SPF/DKIM/DMARC status could not be verified.
 [HIGH] (sender_domain) Display name references 'paypal' but the sending domain ('paypa1-secure-verify.com') has no relation to paypal's real domain — a classic brand-impersonation pattern.
 [HIGH] (sender_domain) Sending domain 'paypa1-secure-verify.com' looks like a character-substituted lookalike of 'paypal.com' (e.g. '0' for 'o', '1' for 'l/i').
 [MEDIUM] (content) Uses urgency/pressure language (9 phrase(s) matched, e.g. 'immediately') designed to rush the reader into acting without thinking.
 [HIGH] (content) Directly asks the reader to confirm/enter credentials or payment details (matched: 'click here to verify').
 [LOW] (content) Uses a generic greeting instead of the recipient's name — mass phishing campaigns rarely personalize this.
======================================================================

======================================================================
 File:    phishing_fake_invoice.eml
 Subject: Overdue Invoice #88213 - Payment Required Today
 From:    Accounts Receivable <billing@globalsupply-invoices.net>
 Score:   42 / 100
 Verdict: Suspicious
----------------------------------------------------------------------
 [MEDIUM] (header) No Authentication-Results header present — SPF/DKIM/DMARC status could not be verified.
 [HIGH] (url) Link points directly to a raw IP address (185.220.101.47) instead of a domain name — legitimate organizations almost never do this.
 [LOW] (content) Uses a generic greeting instead of the recipient's name — mass phishing campaigns rarely personalize this.
======================================================================

======================================================================
 File:    phishing_it_helpdesk.eml
 Subject: ACTION REQUIRED: Mailbox Quota Exceeded
 From:    IT Support Desk <it-support@gmail.com>
 Score:   48 / 100
 Verdict: Suspicious
----------------------------------------------------------------------
 [MEDIUM] (header) No Authentication-Results header present — SPF/DKIM/DMARC status could not be verified.
 [MEDIUM] (sender_domain) Claims to be an official support/security team but sends from a free consumer mail domain ('gmail.com') rather than a corporate domain.
 [MEDIUM] (url) Link uses a URL shortener (bit.ly), which hides the real destination.
 [MEDIUM] (content) Uses urgency/pressure language (3 phrase(s) matched, e.g. 'action required') designed to rush the reader into acting without thinking.
======================================================================
```

**Key takeaway for a portfolio/README:** both legitimate control emails
scored a clean 0, while all three phishing samples were correctly
flagged — including two (the fake invoice and IT helpdesk emails) that
don't impersonate an obvious big brand and rely more on urgency,
free-mail sender abuse, and link cloaking. That's a meaningfully harder
detection case than the obvious "PayPal" lookalike, and the analyzer
still caught them.
