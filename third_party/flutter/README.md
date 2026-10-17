# Vendored Flutter plugins

The desktop UI's git-sourced Flutter plugins, copied from the commits `flutter/pubspec.yaml` pinned before (audit
finding C3, issue #34) so that `flutter pub get` fetches no code from GitHub. Copies are exact `git archive` exports of
those commits (for `uni_links` the two symlinks to its repository root were replaced by the files they point to). Never
edit them by hand: to update one, export the new commit the same way, review the diff, and record it here.

| Package | Upstream repository | Commit |
|---|---|---|
| dash_chat_2 | github.com/rustdesk-org/Dash-Chat-2 | bd6b5b41254e57c5bcece202ebfb234de63e6487 |
| window_manager | github.com/rustdesk-org/window_manager | cf4aef0512092fad9344a27ffe1c47ad83269dfc |
| desktop_multi_window | github.com/rustdesk-org/rustdesk_desktop_multi_window | cddc2e64f8fefce4f80db87b20bcda2dd019bed6 |
| flutter_custom_cursor | github.com/rustdesk-org/flutter_custom_cursor | db63b785c38153603e9fb84b50d3ec46f0d7e05e |
| window_size | github.com/21pages/flutter-desktop-embedding (`plugins/window_size`) | 51e67ce047c72b26810b99e8473ddb44612fe356 |
| uni_links | github.com/rustdesk-org/uni_links (`uni_links`) | f416118d843a7e9ed117c7bb7bdc2deda5a9e86f |
| texture_rgba_renderer | github.com/rustdesk-org/flutter_texture_rgba_renderer | 42797e0f03141dc2b585f76c64a13974508058b4 |
| flutter_gpu_texture_renderer | github.com/rustdesk-org/flutter_gpu_texture_renderer | 08a471bb8ceccdd50483c81cdfa8b81b07b14b87 |
| dynamic_layouts | github.com/rustdesk-org/dynamic_layouts | 24cb88413fa5181d949ddacbb30a65d5c459e7d9 |

Review (2026-10-17, plan section 2ad): source only, no prebuilt binaries; a pattern audit of the Dart and native code
(Windows, Linux) for network, process, telemetry and URL use found only comments, plus one link pattern in dash_chat_2
that this app does not use (its own message builder renders plain text).

The repository's `.gitignore` excludes `*png`; `!/third_party/**` re-includes everything here, because the plugins declare png assets
(`dash_chat_2/assets`, `window_manager/images`) and a build from tracked files must see them.
