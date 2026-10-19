# Upstream workflows (disabled)

These are RustDesk's GitHub Actions workflows, kept for reference only. They are outside `.github/workflows`, so
GitHub does not run them (security review #62, #88): they download unpinned engines, drivers and prebuilt libraries,
sign with the vendor's setup and publish releases, none of which Handover does. Handover is built with
`tools/build-linux.sh`, `tools/build-windows.ps1` and `server/build.sh` (see AGENTS.md and the runbook issue #33).
