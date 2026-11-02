# SpamAssassin baseline (decision D2)

Scores the development emails with SpamAssassin's rules (Bayes off, local tests only, no
network). Run from the repo root:

```powershell
cd ml; python -m phishguard_ml baseline-export; cd ..          # data/baseline/dev_emails.mbox
docker compose --profile baseline run --rm spamassassin        # -> data/baseline/scored.mbox
cd ml; python -m phishguard_ml baseline-import                 # -> data/models/baseline/...
```

An email counts as detected when its score reaches `required` (SpamAssassin's default 5.0).
