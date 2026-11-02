# Signature baseline for emails (decision D2): Apache SpamAssassin rules, Bayes off, local tests
# only. Debian 13's own package (SpamAssassin 4.0.1, Apache License 2.0) with the rules it ships;
# sa-update is never run, so the rule set is fixed by the package version.
FROM debian:13-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends spamassassin \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 scorer
USER scorer
WORKDIR /work
# Reads /work/dev_emails.mbox, writes /work/scored.mbox (one X-Spam-Status header per message).
# report_safe 0: spam is only tagged with headers, not wrapped in a report message (so the
# X-PhishGuard-Id header stays on top).
CMD ["sh", "-c", "spamassassin --version > version.txt && spamassassin --mbox -L -t --cf='use_bayes 0' --cf='bayes_auto_learn 0' --cf='report_safe 0' < dev_emails.mbox > scored.mbox"]
