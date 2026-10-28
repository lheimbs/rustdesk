# Handover CI (not active yet)

`handover-ci.yml` is the fork's own workflow (#92). It lives here, outside `.github/workflows/`, because the
automation token cannot write workflow files and because Actions stays disabled until the default branch no longer
carries the upstream workflows (#91, #88; those are parked in `.github/upstream-workflows/`).

To activate (owner): `git mv .github/handover-ci/handover-ci.yml .github/workflows/`, commit, push, enable Actions
for the repository, and watch the first run. Expected run time: about 3-4 hours on a hosted runner (two fat-LTO
builds plus six 60-second egress scenarios).
