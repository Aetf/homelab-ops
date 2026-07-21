# homelab-ops

Host-side maintenance scripts for Aetf's homelab server. Each script is
driven by a systemd user timer that lives in the (separate) dotfiles repo,
scoped to the homelab host via a yadm `##h.<hostname>` alternate.

## Scripts

- `bin/check-gw` — daily gateway health check: config drift on the UDM-SE
  (via `~/.config/gw-config/deploy.sh --check`) and TLS certificate expiry
  for the internal reverse proxy; mails a report when something is off.
- `bin/gw-backup-pull` — weekly pull of UniFi/AdGuard backups from the
  gateway into `~/.config/gw-config/backups`.
- `bin/check-hath` — periodic health check for the Hentai@Home client
  running in k8s: restarts it when the pod is broken or silent, alerts on
  startup-failure loops.

## Containerized jobs

- `dmarc-check/` — daily DMARC aggregate-report triage. Unlike the `bin/`
  scripts (host shims), this runs in a self-contained image built from
  `dmarc-check/Containerfile` by the mise `projects:sync` task and fired by
  a quadlet `.container` + `.timer`. It fetches unread DMARC reports from the
  Gmail inbox over IMAP, evaluates SPF/DKIM per source, silently reads +
  archives clean ones, and for failures keeps the mail unread + tagged
  `DMARC-Issue`, asks `claude` to triage spoofing-vs-misconfig, and mails an
  alert. Credentials are injected at runtime (`~/.config/dmarc-check/env`);
  claude auth is a mounted host credential. See `dmarc-check/dmarc_check.py`.

## Installation

This repo is its own [vfox tool plugin](https://mise.jdx.dev/tool-plugin-development.html),
installed and pinned globally with [mise](https://mise.jdx.dev):

```toml
[tools]
"vfox:Aetf/homelab-ops" = "<git commit sha or tag>"
```

`mise install` downloads the pinned ref and exposes `bin/` through mise
shims (`~/.local/share/mise/shims/…`), which is the stable path the systemd
units use. `HOMELAB_OPS_HOME` points at the installed copy.
