# Feature catalogue (F1–F140)

Copied from Appendix A (Table A.1) of the proposal. The order and names are fixed: the
extractor must output exactly these features in this order. `ti_score` is not part of
this list; it is a separate model input (RQ2).

| ID | Feature | Group | Description |
|---|---|---|---|
| F1 | url_length | URL lexical | Total number of characters in the URL |
| F2 | hostname_length | URL lexical | Number of characters in the hostname |
| F3 | path_length | URL lexical | Number of characters in the URL path |
| F4 | query_length | URL lexical | Number of characters in the query string |
| F5 | fragment_length | URL lexical | Number of characters after the # sign |
| F6 | num_dots | URL lexical | Count of "." characters in the URL |
| F7 | num_hyphens | URL lexical | Count of "-" characters in the URL |
| F8 | num_underscores | URL lexical | Count of "_" characters in the URL |
| F9 | num_slashes | URL lexical | Count of "/" characters in the URL |
| F10 | num_question_marks | URL lexical | Count of "?" characters in the URL |
| F11 | num_equals | URL lexical | Count of "=" characters in the URL |
| F12 | num_at_symbols | URL lexical | Count of "@" characters (can hide the real host) |
| F13 | num_ampersands | URL lexical | Count of "&" characters in the URL |
| F14 | num_percent | URL lexical | Count of "%" characters (URL encoding) |
| F15 | num_tilde | URL lexical | Count of "~" characters in the URL |
| F16 | num_digits_url | URL lexical | Count of digits in the URL |
| F17 | digit_ratio_url | URL lexical | Digits divided by URL length |
| F18 | letter_ratio_url | URL lexical | Letters divided by URL length |
| F19 | special_char_ratio | URL lexical | Non-alphanumeric characters divided by URL length |
| F20 | has_ip_address | URL lexical | 1 if the host is an IPv4 or IPv6 address |
| F21 | uses_https | URL lexical | 1 if the URL scheme is HTTPS |
| F22 | has_port | URL lexical | 1 if a non-standard port is given in the URL |
| F23 | num_subdomains | URL lexical | Number of subdomain levels before the registered domain |
| F24 | subdomain_length | URL lexical | Number of characters in the subdomain part |
| F25 | tld_length | URL lexical | Number of characters in the top-level domain |
| F26 | suspicious_tld | URL lexical | 1 if the TLD is on a list of TLDs often abused for phishing |
| F27 | is_shortened | URL lexical | 1 if the host is a known URL-shortening service |
| F28 | has_double_slash_redirect | URL lexical | 1 if "//" appears in the path (possible redirect) |
| F29 | has_http_in_path | URL lexical | 1 if "http" or "https" appears inside the path or query |
| F30 | has_punycode | URL lexical | 1 if the host contains an "xn--" (punycode) label |
| F31 | has_mixed_script | URL lexical | 1 if the host mixes character sets (homoglyph risk) |
| F32 | url_entropy | URL lexical | Shannon entropy of the full URL string |
| F33 | hostname_entropy | URL lexical | Shannon entropy of the hostname |
| F34 | longest_token_length | URL lexical | Length of the longest token after splitting on separators |
| F35 | avg_token_length | URL lexical | Average token length in the URL |
| F36 | num_path_tokens | URL lexical | Number of segments in the path |
| F37 | num_query_params | URL lexical | Number of parameters in the query string |
| F38 | suspicious_file_extension | URL lexical | 1 if the path ends in a risky extension (e.g. .exe, .scr, .zip) |
| F39 | brand_in_subdomain | URL lexical | 1 if a known brand name appears in the subdomain |
| F40 | brand_in_path | URL lexical | 1 if a known brand name appears in the path |
| F41 | has_sensitive_word_url | URL lexical | 1 if words like "login", "verify", "secure" or "account" appear |
| F42 | num_sensitive_words_url | URL lexical | Count of sensitive words in the URL |
| F43 | hostname_digit_ratio | URL lexical | Digits divided by hostname length |
| F44 | max_char_repeat | URL lexical | Longest run of the same repeated character |
| F45 | hostname_vowel_ratio | URL lexical | Vowels divided by letters in the hostname |
| F46 | domain_age_days | Domain/SSL | Days since the domain was registered (WHOIS) |
| F47 | domain_expiry_days | Domain/SSL | Days until the domain registration expires |
| F48 | registration_length_days | Domain/SSL | Total registration period in days |
| F49 | whois_available | Domain/SSL | 1 if a WHOIS record could be retrieved |
| F50 | whois_privacy | Domain/SSL | 1 if registrant details are privacy-protected |
| F51 | days_since_whois_update | Domain/SSL | Days since the WHOIS record was last updated |
| F52 | registrant_country_known | Domain/SSL | 1 if a registrant country is listed |
| F53 | num_a_records | Domain/SSL | Number of DNS A records for the host |
| F54 | has_mx_record | Domain/SSL | 1 if the domain has an MX (mail) record |
| F55 | num_name_servers | Domain/SSL | Number of NS records for the domain |
| F56 | dns_min_ttl | Domain/SSL | Lowest DNS time-to-live value (short TTLs suggest fast-flux) |
| F57 | tranco_rank | Domain/SSL | Rank in the Tranco list (0 if not listed) |
| F58 | in_tranco_top_1m | Domain/SSL | 1 if the domain is in the Tranco top one million |
| F59 | ssl_valid | Domain/SSL | 1 if the TLS certificate is valid and trusted |
| F60 | ssl_cert_age_days | Domain/SSL | Days since the certificate was issued |
| F61 | ssl_validity_days | Domain/SSL | Total certificate validity period in days |
| F62 | ssl_free_ca | Domain/SSL | 1 if issued by a free automated CA (e.g. Let's Encrypt) |
| F63 | ssl_hostname_match | Domain/SSL | 1 if the certificate name matches the hostname |
| F64 | ssl_san_count | Domain/SSL | Number of names in the certificate's Subject Alternative Name list |
| F65 | suspicious_asn | Domain/SSL | 1 if the hosting network (ASN) is on a list often used for abuse |
| F66 | num_forms | HTML/JS | Number of <form> elements on the page |
| F67 | num_password_fields | HTML/JS | Number of password input fields |
| F68 | form_action_external | HTML/JS | 1 if a form submits to a different domain |
| F69 | form_action_empty | HTML/JS | 1 if a form action is empty or "about:blank" |
| F70 | form_action_mailto | HTML/JS | 1 if a form submits to a mailto: address |
| F71 | num_input_fields | HTML/JS | Number of <input> elements |
| F72 | num_hidden_inputs | HTML/JS | Number of hidden input fields |
| F73 | num_iframes | HTML/JS | Number of <iframe> elements |
| F74 | has_invisible_iframe | HTML/JS | 1 if an iframe has zero size or is hidden |
| F75 | num_script_tags | HTML/JS | Number of <script> elements |
| F76 | num_external_scripts | HTML/JS | Number of scripts loaded from other domains |
| F77 | has_eval_or_unescape | HTML/JS | 1 if eval() or unescape() is used |
| F78 | has_js_obfuscation | HTML/JS | 1 if atob() or String.fromCharCode() is used heavily |
| F79 | has_js_redirect | HTML/JS | 1 if JavaScript changes window.location |
| F80 | has_meta_refresh | HTML/JS | 1 if a <meta http-equiv="refresh"> tag is present |
| F81 | disables_right_click | HTML/JS | 1 if the page blocks the right-click menu |
| F82 | has_popup_window | HTML/JS | 1 if window.open() or prompt() is used |
| F83 | num_links | HTML/JS | Total number of <a> links |
| F84 | external_link_ratio | HTML/JS | Share of links pointing to other domains |
| F85 | null_link_ratio | HTML/JS | Share of links that are "#" or "javascript:void(0)" |
| F86 | favicon_external | HTML/JS | 1 if the favicon is loaded from another domain |
| F87 | external_resource_ratio | HTML/JS | Share of images and stylesheets loaded from other domains |
| F88 | title_brand_mismatch | HTML/JS | 1 if the page title names a brand that is not in the domain |
| F89 | copyright_brand_mismatch | HTML/JS | 1 if the copyright notice names a brand not in the domain |
| F90 | html_length | HTML/JS | Size of the HTML source in characters |
| F91 | num_hidden_elements | HTML/JS | Number of elements hidden with CSS (display:none, visibility:hidden) |
| F92 | has_login_keywords_page | HTML/JS | 1 if page text contains "sign in", "log in" or "password" |
| F93 | num_images | HTML/JS | Number of <img> elements |
| F94 | text_to_html_ratio | HTML/JS | Visible text length divided by HTML length |
| F95 | has_base64_content | HTML/JS | 1 if the page embeds base64 data URIs |
| F96 | spf_pass | Email header | 1 if SPF result is "pass" |
| F97 | spf_fail | Email header | 1 if SPF result is "fail" or "softfail" |
| F98 | dkim_pass | Email header | 1 if a DKIM signature verifies |
| F99 | dkim_absent | Email header | 1 if the message has no DKIM signature |
| F100 | dmarc_pass | Email header | 1 if DMARC result is "pass" |
| F101 | dmarc_policy_strict | Email header | 1 if the sender domain's DMARC policy is quarantine or reject |
| F102 | from_replyto_mismatch | Email header | 1 if the Reply-To domain differs from the From domain |
| F103 | from_returnpath_mismatch | Email header | 1 if the Return-Path domain differs from the From domain |
| F104 | display_name_spoof | Email header | 1 if the display name names a brand not matching the sender domain |
| F105 | sender_in_tranco | Email header | 1 if the sender domain is in the Tranco top one million |
| F106 | num_received_headers | Email header | Number of Received: hops |
| F107 | received_chain_inconsistent | Email header | 1 if the Received: chain has gaps or impossible hops |
| F108 | message_id_domain_mismatch | Email header | 1 if the Message-ID domain differs from the From domain |
| F109 | suspicious_mailer | Email header | 1 if X-Mailer names a known bulk or phishing kit tool |
| F110 | date_header_anomaly | Email header | 1 if the Date header is missing or far from receipt time |
| F111 | html_only | Email header | 1 if the email has HTML but no plain-text part |
| F112 | num_attachments | Email header | Number of attachments |
| F113 | risky_attachment_type | Email header | 1 if any attachment is .exe, .js, .html, .zip, .iso or macro-enabled |
| F114 | num_urls_in_email | Email header | Number of URLs found in the email body |
| F115 | link_text_mismatch | Email header | 1 if a link's visible URL differs from its real target |
| F116 | num_brand_mentions | NLP text | Count of known brand names in the text |
| F117 | num_urgency_terms | NLP text | Count of urgency words (e.g. "immediately", "urgent") |
| F118 | num_threat_terms | NLP text | Count of threat words (e.g. "suspended", "locked") |
| F119 | num_reward_terms | NLP text | Count of reward words (e.g. "prize", "refund") |
| F120 | num_credential_terms | NLP text | Count of credential words (e.g. "password", "verify") |
| F121 | num_financial_terms | NLP text | Count of money and payment words |
| F122 | generic_greeting | NLP text | 1 if the text opens with a generic greeting ("Dear customer") |
| F123 | subject_urgency_terms | NLP text | Count of urgency words in the subject line |
| F124 | fake_reply_subject | NLP text | 1 if the subject starts with "RE:" or "FW:" without a real thread |
| F125 | subject_length | NLP text | Number of characters in the subject line |
| F126 | word_count | NLP text | Number of words in the body |
| F127 | uppercase_ratio | NLP text | Uppercase letters divided by all letters |
| F128 | exclamation_count | NLP text | Number of "!" characters |
| F129 | spelling_error_ratio | NLP text | Misspelled words divided by total words |
| F130 | readability_score | NLP text | Flesch reading-ease score of the body |
| F131 | avg_sentence_length | NLP text | Average words per sentence |
| F132 | call_to_action_count | NLP text | Count of phrases such as "click here" or "act now" |
| F133 | sentiment_polarity | NLP text | Sentiment score from -1 (negative) to +1 (positive) |
| F134 | lexical_diversity | NLP text | Unique words divided by total words |
| F135 | num_currency_symbols | NLP text | Count of currency symbols and codes |
| F136 | num_phone_numbers | NLP text | Count of phone numbers in the text |
| F137 | non_ascii_ratio | NLP text | Non-ASCII characters divided by all characters |
| F138 | phishing_lexicon_score | NLP text | Weighted score from a fixed phishing word list |
| F139 | deadline_mention | NLP text | 1 if a deadline is given (e.g. "within 24 hours") |
| F140 | brand_sender_mismatch | NLP text | 1 if a brand named in the text does not match the sender domain |
