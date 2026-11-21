# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.6.0] - 2026-11-21

### Upgrade notes

- **Cisco ASA, Cisco IOS and F5 events carry the device's hostname in
  `dvchost` instead of `shost`.** The syslog header host of these
  appliances is the reporting device, not the source of the traffic, so
  CEF's device field is the right place for it (#135). SIEM rules or
  parsers that read `shost` for these devices must read `dvchost`. A
  hostname longer than `dvchost`'s 100-character limit stays in `shost`,
  so no value is lost and `--strict` still accepts it. FortiGate, Sophos,
  VMware and Linux output is unchanged.

### Added

- Template fields `device_host` (the host when it fits `dvchost`) and
  `device_host_long` (the host when it is longer), for custom mappings
  that want the same split. Both are reserved names in pattern files.

### Fixed

- With a forced `--mode`, a line the parser rejects (or that makes a
  `register_parser()` function raise) no longer stops the stream. The CLI
  converts it as a raw-message event and logs one warning, then further
  rejections at DEBUG; `--stats` counts them as unrecognized. A single
  malformed datagram can no longer stop a `--listen` receiver. Library
  callers of `StreamConverter` keep the previous behavior (a
  `ParserError`) unless they pass `on_parse_error="raw"`.

## [0.5.0] - 2026-11-21

Custom parsers become a short, testable loop: pattern files can capture any
field, match just the message, use regex shorthands, choose a mapping and
carry their own examples, and `--explain`, `--stats` and `--check-patterns`
show what happened to each line. Existing pattern files and normal CEF
output are unchanged, with one exception noted under Fixed: KV and Cisco
records that name an unambiguous timezone (`timezone="CEST"`,
`04:00:47 PST`) are now dated in that zone, so their `rt` moves by the
offset compared with 0.4.x.

### Added

- Msg patterns: a pattern with `"match": "msg"` is applied to the message of
  every parsed event, whatever parser read the header, and turns its named
  groups into fields. An optional `app` key limits it to events from given
  programs (`"app": ["sshd", "sshd-session"]`). This covers the common case
  of a device whose syslog header is already understood but whose message
  text carries the values a SIEM needs, without matching the whole line.
- Line patterns keep every named group beyond `pri`, `host`, `app`, `pid`,
  `msgid`, `msg` and `ts` as a field instead of rejecting it. Captured fields
  from either kind of pattern are available to mapping templates
  (`%(src)s`), replace a same-named key=value pair from the message, and get
  the usual alias handling (`src_ip` also provides `src`).
- Regex shorthands in pattern files: `%{IP:src}`, `%{PORT:spt}`,
  `%{USER:suser}`, `%{TIMESTAMP_ISO8601:ts}` and 14 more insert a tested
  regex, captured under the given name, so common values need no
  hand-written regex. `%{NAME}` without a field name matches without
  capturing. An unknown name fails at load time and lists the known ones.
- A pattern's `mapping` key names a bundled mapping or a mapping file
  (relative to the pattern file) for the events it matches. It is validated
  at load time; `--mapping` still takes precedence.
- Pattern `examples` (`line`, `expect`, `matches`) and `--check-patterns`,
  which runs them through the normal pipeline, prints `PASS`/`FAIL` per
  example and exits 1 on any failure, so pattern files can be tested before
  a service restart or in CI.
- `--explain` prints, for each input line, the parser, the line and msg
  patterns that matched, where the mapping came from, every field available
  to mapping templates, and the resulting CEF record.
- `--stats` prints a summary to stderr when input ends: lines by parser and
  by msg pattern, and the number of lines no parser recognized with the
  first few of them. It works alongside normal output, `--output`, `--send`
  and `--explain`.
- An optional `description` key on patterns, for notes; syslogcef ignores it.
- `docs/patterns.md`, a pattern authoring guide with an OpenSSH walkthrough,
  and example files under `examples/patterns/`. The README and man page
  document the new keys and flags.

### Changed

- An unknown key in a pattern or example (for instance a misspelled
  `"exmaples"`) is still ignored, so the file keeps loading, but it is now
  logged as a warning naming the file, pattern and key, and
  `--check-patterns` reports it as a failure (`FAIL <pattern> config:
  unknown key 'exmaples'`) and exits 1.

### Fixed

- Ctrl-C (SIGINT) now stops a run, typically `--tail` or `--listen`, with
  exit status 130 instead of a `KeyboardInterrupt` traceback.
- An `app`-filtered msg pattern is chosen after a continuation line inherits
  its app, in load order, so it applies exactly as on a normal line.
- `%{IPV6}` and `%{IP}` capture IPv4-mapped addresses (`::ffff:192.0.2.1`)
  whole.
- `--tail` reads at most 100 lines per file per pass, so one busy file no
  longer starves the others; holds a half-written line until its newline
  arrives instead of emitting it as two events; and checks for a
  copy-truncate before each read, so the rewritten start of a file is no
  longer skipped.
- `--listen tcp` no longer closes a connection as idle while records it sent
  are still waiting to be read.
- `--multiprocess` keeps parsers registered with `register_parser()` in the
  worker processes, including one that replaces a file pattern's name.
  `register_parser(..., replace=True)` also removes the replaced pattern from
  auto-detection.
- A pattern `timestamp_format` containing a literal `%%Y` gets the inferred
  year instead of 1900.
- Cisco timestamp fractions longer than three digits no longer lose a
  microsecond.
- Invalid numeric KV timezone offsets (`tz=-1260`, `tz=+00:99`) are ignored
  instead of being silently normalized. Named zones in KV records and Cisco
  timestamps are applied when unambiguous; CST, IST, BST and AST stay
  unresolved.
- `--strict` timestamp validation no longer rejects English month names
  under a non-English locale.
- A plain `event_code=` field no longer routes a line to the Cisco IOS
  mapping or sets its severity; only a `%FAC-SEV-MNEMONIC` code does.
- `dvcpid` is emitted for a numeric key=value `pid=` when the header has no
  PID.
- A mapping template that cannot render an event logs one warning, then
  debug messages, instead of a warning per event.
- The Debian package restarts running `syslogcef` and `syslogcef@*` services
  on upgrade, so they run the new version.
- Releases publish the container image and PyPI only after every package
  build has succeeded, and the GitHub release waits for the image.
- Documentation: the "never aborts" guarantee applies to auto-detection (a
  forced `--mode` stops at the first line it rejects); header CR/LF are
  replaced with spaces; RPM signatures are embedded (no `.asc`); the man
  page's logrotate and `--mapping` text, the demo and the CEF 0.1 IPv4-only
  rule are corrected.

## [0.4.2] - 2026-11-21

Completes the 0.4.1 release. 0.4.1 reached PyPI and the container
registry, but its RPM build failed, so it has no GitHub release, RPM, Debian
or Alpine package, or zipapp. Use 0.4.2 for those; it contains everything in
0.4.1.

### Fixed

- The test suite passes when run from the sdist, as the RPM `%check` does.
  Three tests added with the rename read the CHANGELOG, the man page source
  and the signing keys, which the sdist does not ship; they now skip when
  those files are absent and still run in a git checkout. CI also runs the
  suite from a freshly built sdist, so this is caught before a release.

## [0.4.1] - 2026-11-21

### Changed

- The project, GitHub repository, and the RPM, Debian and Alpine packages are
  now all named `syslog2cef`, matching the PyPI distribution and removing the
  long-standing mismatch. The container image is now
  `ghcr.io/allamiro/syslog2cef`, and release artifacts are named
  `syslog2cef-X.Y.Z.*`.
- **Unchanged, deliberately:** the `syslogcef` command, the importable
  `syslogcef` Python package, the config paths (`/etc/syslogcef/`), the
  systemd unit names, the log directory and the `syslogcef` system user. An
  existing install therefore keeps working across the rename. The RPM
  carries `Provides`/`Obsoletes`, so `dnf upgrade` from the COPR repository
  migrates automatically. The Alpine package carries `provides`/`replaces`
  and the Debian package a versioned `Provides` plus `Replaces`/`Conflicts`,
  which let each take over an installed `syslogcef` when the artifact is
  installed directly — the way both are distributed. Debian has no
  `Obsoletes` equivalent, so there is no repository-driven `apt upgrade`
  migration; there is also no apt repository for this project.
- The COPR project keeps its existing name, `allamiro/syslogcef`, because
  renaming it would break every user who has already enabled it. The
  packages it builds are named `syslog2cef` from this release on.
- The signing keys keep their filenames and UID (`RPM-GPG-KEY-syslogcef`,
  `packaging/apk/syslogcef.rsa.pub`, "syslogcef release signing"): renaming
  them would invalidate verification for anyone who already imported them.

### Fixed

- `python -m syslogcef --help` reports `usage: syslogcef` instead of
  `usage: __main__.py`.

## [0.4.0] - 2026-11-21

This release changes emitted CEF in two ways that downstream SIEM content
may depend on: Cisco ASA records now carry the raw line in `cs1`, and
yearless timestamps are dated in the past (see Fixed). Review parsers or
rules that read ASA `cs1` or that relied on the previous year inference.

### Added

- `syslogcef --version` prints the version, copyright, license and author
  in the GNU format (first line `syslogcef X.Y.Z`); the version is also
  available as `syslogcef.__version__`. The man page gains `--version`,
  `--help` and a COPYRIGHT section. Conversion output is unchanged: stdout
  still carries only CEF records.
- `CITATION.cff` with software citation metadata, so GitHub offers "Cite
  this repository"; the README has a matching BibTeX entry and status badges.
- Per-version Python classifiers (3.9 to 3.14) in the package metadata.

### Fixed

- Timestamps without a year are no longer dated into the next year (#112).
  The year came from a symmetric 180-day window around the current time, so
  converting a `Jan  1` line in November produced next January. A yearless
  timestamp now takes its most recent occurrence no more than one day ahead
  of the current time, which still handles a line stamped just after
  midnight on New Year's Eve. The built-in parsers, the adaptive parser and
  custom `--patterns` share the rule, and a yearless Feb 29 resolves to the
  last leap day in the past rather than the nearest one.
- The Cisco ASA mapping no longer emits `cs1Label=rawEvent` without a `cs1`
  value (#111). Its `cs1` came from the message's key=value pairs, which most
  ASA messages do not have, so the value was dropped while the constant label
  stayed. `cs1` now carries the raw line, like every other bundled mapping.
  More generally, a custom-field label (`cs1Label`, `cn1Label`,
  `flexString1Label`, ...) is now dropped whenever its paired value resolves
  empty, so a mapping can no longer produce a label that describes nothing.
- COPR builds no longer fail after a version bump. The COPR project builds
  every push to `main` with rpkg, and the spec's `Source0` is the PyPI sdist,
  which does not exist yet when the "Bump version" commit lands on `main`
  (the release workflow publishes it a few minutes later), so every webhook
  build of a new version failed downloading it. When rpkg preprocesses the
  spec, a project macro (`packaging/rpm/rpkg.macros`, registered by
  `packaging/rpm/rpkg.conf`) now generates that tarball from the git
  checkout, so COPR builds package the pushed commit and never depend on
  PyPI. The spec is unchanged for plain `rpmbuild` and the release workflow.

## [0.3.3] - 2026-08-12

### Fixed

- Adaptive parsing no longer lets a cached hostless layout suppress hosts on
  later lines with the same reduced signature. Cached hosts now normalize
  trailing delimiters consistently, named timezone remnants are not treated
  as hosts, IP host tokens are accepted, and `ts_orig` is retained.
- Normalization now treats parsed syslog envelope metadata as authoritative
  over same-named message key/value pairs, preventing payload fields such as
  `host=` and `severity=` from changing mapped metadata. Field-name matching
  is case-insensitive while original spellings remain available.
- Key/value extraction supports escaped quotes and comma-delimited pairs
  without splitting ordinary comma-containing values.
- Python mapping dictionaries receive the same eager structural validation as
  JSON mapping files. Invalid header/extension templates, severity maps, and
  extension keys now fail clearly instead of raising during rendering or
  producing structurally invalid CEF.
- Malformed `%`-format templates are rejected when the mapping is loaded
  rather than degrading silently per event. Previously a template such as
  `%{msgid}` or a literal `100% clean` rendered as an empty string, which
  fell a header back to its default or dropped an extension without any
  indication in the output. Use `%%` for a literal percent sign. Templates
  whose syntax is valid but whose conversion a given value cannot satisfy
  (`%(dpt)d` against a non-numeric field) still degrade gracefully at render
  time, so a malformed mapping can no longer be discovered only after
  millions of records have been written.
- Case normalization of canonical CEF keys no longer depends on the order
  fields appear in a message: an explicitly lowercase `deviceexternalid=`
  now wins over `DEVICEEXTERNALID=` in either order.
- A record with no recognized envelope timestamp no longer hides a payload
  `ts_orig=` value: an empty envelope timestamp counts as absent rather
  than overwriting the message field.
- Comma-delimited key/value streams of short values (`a=1, b=2, c=3`) are
  still detected as key/value records now that separators are excluded from
  matched values.
- More named timezone abbreviations (BST, IST, JST, KST, AEST, MSK, NZDT,
  SAST and similar) are rejected as adaptive hostnames. Abbreviations that
  double as ordinary words (WEST, CAT, EAT, ART) are deliberately still
  accepted, since dropping a genuine short hostname is the worse failure.
- A hostname followed by a multi-character delimiter (`host::`, `host:,`)
  is recognized again on both the analysis and cached adaptive paths.
- Mapping validation runs once per stream instead of once per record, so a
  malformed mapping is reported when `StreamConverter` is constructed and
  long runs do not re-validate templates for every event.

### Changed

- **Behavior change.** A mapping with a malformed template is now a
  configuration error (`ValueError`) instead of being tolerated with
  degraded output. All bundled mappings validate cleanly; a custom mapping
  that relied on the previous silent fallback must quote literal percent
  signs as `%%`.

## [0.3.2] - 2026-08-12

### Fixed

- The syslog HOSTNAME now maps to `shost` (source host) instead of
  `dhost` (destination): the host that emitted a syslog line is the
  event's source, not a destination. `dhost` stays reserved for
  network-specific logs whose payload names a real destination. Applied
  in the bundled Linux mapping and the default mapping (`shost`, max
  1023 chars, so long RFC 5424 hostnames still pass `--strict`).
- An ordinary RFC3164 / journald-short line whose message body carries
  `key=value` pairs (containerd, dockerd, NetworkManager, systemd) is no
  longer misparsed as the kv format: the header-based parsers now run
  before the kv detector, so host/app are extracted and the syslog
  header is not leaked into the message. Genuine kv streams (Fortinet,
  Sophos) still parse as kv.

## [0.3.1] - 2026-08-11

### Fixed

- Continuation context is scoped per input source: with several input
  files (or several files tailed at once, which interleave), an
  indented line now inherits host/app/timestamp only from its own
  file's preceding event, never from another file's.
- A forced `--mode` no longer aborts on whitespace-indented
  continuation lines: with context available they inherit as in
  auto-detect mode; without context the parser error is still raised.
- `dvcpid=` is emitted only for numeric pids: RFC 5424 PROCID may be an
  arbitrary string ("worker-A"), and the CEF dictionary types dvcpid as
  an integer, so non-numeric identifiers previously produced invalid
  output that `--strict` rejected. They remain available as `%(pid)s`.

## [0.3.0] - 2026-08-11

### Added

- Event time in the CEF output: every event now carries `rt=` (epoch
  milliseconds) from the parsed timestamp, or the processing time when
  the line had no usable timestamp. The bundled Linux mapping also
  emits `dvcpid=` for the syslog tag's pid.
- Continuation-line handling for multi-line records (macOS install.log
  and system.log wrapped payloads, stack traces): whitespace-indented
  lines inherit host, program, pid, PRI, and timestamp from the
  preceding event instead of getting the local machine's hostname —
  which, inside a container, was the container ID. Available in the
  sequential CLI pipeline and as `syslogcef.StreamConverter`; not
  applied under `--multiprocess`.
- The adaptive parser now recognizes a syslog program tag
  (`app:` / `app[pid]:`) after the host token and maps it to the
  process/pid fields instead of leaving it in the message, on both the
  first-sight analysis and the cached-pattern path.

### Fixed

- Compact UTC offsets as written by macOS install.log
  (`2026-07-20 03:23:05+02`) and colonless offsets (`+0200`) parse
  correctly in the ISO syslog, rsyslog-file, and journald-ISO formats
  and in `parse_iso8601` — including on Python 3.9/3.10, where
  `fromisoformat` only accepts the `+02:00` form. Previously such
  lines fell through to the adaptive parser, which lost the hostname
  and program because the stray `+02` token blocked host detection.
- `journald_short` and `journald_iso` split `app[pid]:` tags into
  program and pid instead of reporting `opendirectoryd[69]` as the
  program name.

## [0.2.1] - 2026-08-11

### Fixed

- The standalone zipapp works again — and for the first time actually
  works on Python 3.9: `dictionary.json` was read via a filesystem path
  (broke the v0.2.0 `.pyz` build), and the mapping loader anchored
  `importlib.resources` on `__package__`, which is None under Python
  3.9's legacy zipimport. Both loaders use explicit package anchors,
  and a regression test imports the package from inside a zip archive.

## [0.2.0] - 2026-08-11

### Added

- The CEF field dictionary (`syslogcef/dictionary.json`): 176 keys with
  type, maximum length, and producer/consumer scope (including the full
  Event Consumers table and the CEF 1.2 fields), plus 56 source-field
  aliases (`srcip` -> `src`, `dstport` -> `dpt`, `user` -> `suser`,
  `rcvdbyte`/`sentbyte` -> `in`/`out`, ...) applied during
  normalization for every event — including adaptively-parsed unknown
  formats — so mappings and validation always see canonical CEF keys.

### Changed

- The built-in fallback mapping carries the raw line as `cs1` +
  `cs1Label=rawEvent` (like every bundled mapping) instead of setting
  the consumer-only `rawEvent` key, per the ArcSight dictionary rule
  that producers must not set consumer-side fields. Downstream content
  keyed on `rawEvent=` in default-mapped output must read `cs1=`.
- `--validate`/`--strict` warn (non-fatally) when producer output sets
  a consumer-side CEF key, and validate the CEF 1.2 fields' types and
  lengths; the validation table is loaded from the shared dictionary.
- A custom mapping overriding either member of the default
  `cs1`/`cs1Label` pair drops both defaults, so custom values are never
  mislabeled `rawEvent`.

## [0.1.6] - 2026-08-11

### Fixed

Eleven robustness and correctness bugs found by the new fuzzing
infrastructure (grammar-based property tests, ClusterFuzzLite, and AI
review), each with a regression test:

- The journald JSON parser claimed any JSON object: rsyslog-style
  records lost their host, message, and timestamp. It now requires
  journald-style keys and routes rsyslog-marker shapes to the rsyslog
  parser, which also gained `@timestamp`/`timereported` and `syslogtag`
  support.
- kv streams: `ts=`/`timestamp=`/`datetime=` ISO keys are parsed (was:
  only `date=`+`time=`/`eventtime=`); timestamp aliases in both kv and
  rsyslog records are tried independently, so an invalid value no
  longer masks a valid one; `ts_orig` records the value that parsed;
  out-of-range `tz=` offsets and epoch values are ignored instead of
  raising.
- Severity resolution can no longer crash or corrupt the header: a
  non-numeric kv `pri=`, Unicode digits (`severity=²`), and
  multi-thousand-digit values (Python 3.11+ int-conversion limit) all
  fall back to the default; the resolved value is validated to numeric
  0-10.
- Yearless `Feb 29` timestamps no longer crash when the converting
  host's clock is in a non-leap year, and resolve to the nearest leap
  year in time.
- Non-string JSON scalars (`"message": 123`) are coerced instead of
  crashing sanitization.

### Added

- ClusterFuzzLite coverage-guided fuzzing on every parser-touching PR,
  a structure-aware fuzz harness generating six syslog dialects, a seed
  corpus, grammar-based property tests with planted field values, and a
  ready-to-submit OSS-Fuzz kit (see `fuzz/README.md`).
- `docs/cef_fields.md`: ArcSight producer-vs-consumer rules, CEF
  version notes, and a validated sample record.

## [0.1.5] - 2026-08-11

### Added

- `--output` accepts strftime codes (e.g.
  `/var/log/syslogcef/%Y-%m-%d/events-%H.cef`); the file is reopened
  when the rendered path changes (checked at most once per second,
  rendered with an aware local time so `%z`/`%Z` work), parent
  directories are created, and templated paths always append. Codes
  are validated against a portable allowlist at startup; `%%` is a
  literal percent and keeps plain truncate/append semantics.
- `syslogcef@.service` template unit: run several independent pipelines,
  each configured by its own file in `/etc/syslogcef/conf.d/` (a
  commented `example.conf.sample` is installed). The Alpine OpenRC
  service supports the same via symlinked instances.
- Logrotate snippet (`/etc/logrotate.d/syslogcef`) for flat `.cef`
  archives, using copytruncate.
- User-defined parsers: `--patterns file.json` loads named regexes
  whose named groups map to event fields, with strptime/iso8601/epoch
  timestamps, before/after precedence, and eager startup validation;
  pattern names work as `--mode` values and per service instance via
  conf.d. From Python: `register_parser()` and `load_patterns()`.
- Property-based fuzz tests (hypothesis, `fuzz` extra) verifying the
  pipeline never crashes, emits structurally valid CEF, stays within a
  per-line time budget, and keeps the adaptive cache bounded — run on
  every change, plus a weekly 10k-example deep run and an Atheris
  harness in `fuzz/`.
- CI now lints (ruff, shellcheck, hadolint) and builds + smoke-tests
  the container image on every change; issues and pull requests are
  auto-labeled and assigned.

### Changed

- An empty `--output` value means stdout, so `OUTPUT_FILE=` in the
  service environment file logs to the journal instead of misparsing
  the following arguments; `${OUTPUT_FILE}` is expanded unsplit in the
  systemd units and quoted in the OpenRC script.
- The container image runs as numeric UID 65534 so non-root execution
  is verifiable by container runtimes.
- The RPM `%check` runs the full test suite instead of only an import
  check.

## [0.1.4] - 2026-08-11

### Fixed

- TCP listener buffers are capped at 1 MiB per connection; clients
  streaming data without newlines are dropped instead of exhausting
  memory.
- Listen-mode stdout flushes per record when redirected.
- Kafka delivery futures are observed; asynchronous failures raise on
  the next send and on close instead of being silently lost.
- The `--eps` limiter keeps full spacing after processing pauses, and
  `--eps 0` is rejected.
- Validation: IPv4-typed fields reject IPv6 (use c6a1-c6a4), the nine
  standard `oldFile*` keys are validated, and timestamps are parsed
  rather than shape-matched.
- The man page no longer claims the packaged service runs without
  root; the unit documents how to drop privileges with `User=`.

## [0.1.3] - 2026-08-11

### Added

- Network input: `--listen udp:PORT` / `tcp:PORT` turns syslogcef into a
  syslog receiver feeding the conversion pipeline directly.
- Network output: `--send udp://HOST:PORT`, `tcp://HOST:PORT` (with
  reconnect and backoff), or `kafka://BROKER:PORT/TOPIC` (via
  `pip install syslog2cef[kafka]`); `--eps` rate-limits forwarding.
  Combinable with `--output` and `--listen` for a complete
  receive-convert-forward daemon.
- CEF validation: `--validate` checks extensions against the ArcSight
  dictionary (types, lengths, IP/MAC/port/timestamp formats) and warns;
  `--strict` fails on violations. Also available via the API
  (`convert_line(..., validate=True, strict=True)`).
- Comprehensive syslogcef(1) man page covering every option with eight
  examples.
- The systemd unit carries CAP_NET_BIND_SERVICE so port 514 can be
  bound without root; the service config documents network daemon mode.

### Fixed

- Empty CEF header slots are no longer possible: header templates that
  resolve empty fall back to the default mapping template.
- kv timestamps honor numeric `tz=` offsets; native Cisco timestamps
  keep milliseconds; adaptive month-day timestamps use year-rollover
  inference; cached adaptive patterns revalidate host candidates and
  preserve empty messages.

## [0.1.2] - 2026-08-11

Validated against all 543 filebeat module test logs from elastic/beats
(103,837 lines, zero crashes).

### Fixed

- RFC3164 timestamps may include a year (`Oct 10 2018 12:34:56`), the
  format real Cisco ASA/FTD devices emit.
- Hostnames followed by a trailing or standalone colon now parse.
- Cisco `%FAC-SEV-MNEMONIC` event codes are extracted from anywhere in
  the message (IOS sequence-numbered lines), and their severity digit is
  used when the line has no PRI.
- The raw fallback parser preserves a leading `<PRI>` (Sophos XG style),
  keeping facility and severity.
- Auto-mapping routes FTD event codes to the ASA mapping and other Cisco
  codes to the IOS mapping.

## [0.1.1] - 2026-08-10

### Added

- `syslogcef(1)` man page, installed by the RPM, Debian, and Alpine
  packages.
- Multi-arch (amd64/arm64) container image published to
  `ghcr.io/allamiro/syslogcef` on each release.
- COPR repository (`allamiro/syslogcef`) building for Fedora, EPEL 9/10,
  and CentOS Stream 9/10 on x86_64 and aarch64, rebuilt automatically on
  every push.

### Fixed

- Python 3.9 compatibility: dataclasses no longer use `slots=True`
  (a Python 3.10 feature), so the declared `requires-python >= 3.9` is
  accurate again.
- EPEL 9 RPM builds use the python3.11 stack, whose setuptools supports
  PEP 621 metadata.

## [0.1.0] - 2026-08-10

Initial release.

### Added

- Python package with parsers for RFC3164, RFC5424, rsyslog (JSON and file
  formats), and systemd journal exports (JSON, short, and ISO formats), with
  automatic format detection.
- Normalization layer deriving key/value pairs, event codes, and common
  fields from raw messages.
- CEF renderer with JSON-configurable mappings; bundled mappings for Cisco
  ASA, Cisco IOS, F5, generic Linux, and VMware.
- Command line interface with stdin/file input, output file support, tail
  (follow) mode, and optional multiprocessing.
- Release packaging: PyPI distribution (as `syslog2cef`), signed RPM and
  Debian packages with a systemd service, signed Alpine APK with an
  OpenRC service, standalone executable zipapp, and source zip — all
  GPG-signed with a signed SHA256SUMS manifest.
- Test suite and GitHub Actions CI.

### Fixed

- Default Linux mapping contained an invalid template that crashed every
  conversion routed to it.
- CEF header fields are now escaped so crafted log content cannot forge
  header fields or split records.
- `--tail` now follows all given input files instead of blocking on the
  first one.

[Unreleased]: https://github.com/allamiro/syslog2cef/compare/v0.6.0...HEAD
[0.6.0]: https://github.com/allamiro/syslog2cef/compare/v0.5.0...v0.6.0
[0.5.0]: https://github.com/allamiro/syslog2cef/compare/v0.4.2...v0.5.0
[0.4.2]: https://github.com/allamiro/syslog2cef/compare/v0.4.1...v0.4.2
[0.4.1]: https://github.com/allamiro/syslog2cef/compare/v0.4.0...v0.4.1
[0.4.0]: https://github.com/allamiro/syslog2cef/compare/v0.3.3...v0.4.0
[0.3.3]: https://github.com/allamiro/syslog2cef/compare/v0.3.2...v0.3.3
[0.3.2]: https://github.com/allamiro/syslog2cef/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/allamiro/syslog2cef/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/allamiro/syslog2cef/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/allamiro/syslog2cef/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/allamiro/syslog2cef/compare/v0.1.6...v0.2.0
[0.1.6]: https://github.com/allamiro/syslog2cef/compare/v0.1.5...v0.1.6
[0.1.5]: https://github.com/allamiro/syslog2cef/compare/v0.1.4...v0.1.5
[0.1.4]: https://github.com/allamiro/syslog2cef/compare/v0.1.3...v0.1.4
[0.1.3]: https://github.com/allamiro/syslog2cef/compare/v0.1.2...v0.1.3
[0.1.2]: https://github.com/allamiro/syslog2cef/compare/v0.1.1...v0.1.2
[0.1.1]: https://github.com/allamiro/syslog2cef/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/allamiro/syslog2cef/releases/tag/v0.1.0
