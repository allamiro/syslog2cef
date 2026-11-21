# Writing pattern files

syslogcef understands the common syslog formats out of the box, but it cannot
know what the text inside a message means. An OpenSSH login, a firewall deny,
or a VPN session event all arrive as one free-text `msg` and leave as one CEF
`msg=` field, with no `src=`, `suser=` or `outcome=` for your SIEM to search on.

A pattern file fixes that without writing code. It is a JSON file of named
regular expressions. Each named group in a regex (`(?P<src>...)`, or the
shorthand `%{IP:src}`) becomes a field, and a mapping file turns those fields
into CEF extensions. You load it with `--patterns FILE`.

This guide is for people who need to get an unfamiliar device into CEF and do
not write regular expressions every day. It starts with the workflow, using
OpenSSH as the worked example, and ends with a reference.

- [Workflow: OpenSSH logins, step by step](#workflow-openssh-logins-step-by-step)
- [Line patterns and msg patterns](#line-patterns-and-msg-patterns)
- [Reference](#reference): pattern keys, shorthands, reserved names, examples,
  mappings, error messages
- [Keeping regexes fast (ReDoS)](#keeping-regexes-fast-redos)
- [Troubleshooting](#troubleshooting)

The finished files from this guide are in
[examples/patterns/](../examples/patterns/).

## Workflow: OpenSSH logins, step by step

The goal: turn these two lines from `/var/log/secure` into CEF records that
carry the source address, source port, user name and result.

```text
<38>Nov 21 10:15:02 bastion sshd[2211]: Failed password for invalid user admin from 203.0.113.7 port 52144 ssh2
<38>Nov 21 10:15:09 bastion sshd[2214]: Accepted publickey for deploy from 198.51.100.4 port 40022 ssh2
```

Every output in this guide was produced by running the command shown, on
21 November 2026, from a source checkout: the files under
[examples/patterns/](../examples/patterns/) stood in for
`/etc/syslogcef/patterns/`, and
[examples/patterns/secure.log](../examples/patterns/secure.log), which holds
the two lines above, stood in for `/var/log/secure`. The year of a yearless
syslog timestamp, and therefore `rt=`, depends on the day you run the command
(see "Timestamps without a year" in the README).

### 1. Find the lines that need work: `--stats`

Run your log through syslogcef with `--stats` and throw the CEF away. The
summary goes to stderr after the input ends:

```bash
syslogcef --stats /var/log/secure > /dev/null
```

```text
syslogcef: 2 lines
  by parser:
    rfc3164  2
  unmatched (adaptive or unknown): 0
```

Read it this way:

- **by parser** counts lines by the parser that read the syslog header
  (`rfc3164`, `rfc5424`, `journald`, `custom:<name>` for your own line
  patterns, ...).
- **unmatched** counts lines no parser recognized. They were handled by the
  adaptive fallback (which guesses at a layout) or kept as a raw-message
  event. Up to five of them are printed, each cut at 200 characters. If this
  number is high, the header format itself is unknown and you need a
  [line pattern](#line-patterns-and-msg-patterns).
- **by msg pattern** counts lines your msg patterns matched. The section is
  left out when none matched, as above.

Here every line has a known header (RFC3164), so the problem is not the
header. The problem is that nothing reads the message text. That calls for a
msg pattern.

`--stats` also works alongside normal output, `--output`, `--send` and
`--explain`, so you can leave it on a running pipeline. It cannot be combined
with `--multiprocess`. It also prints when you stop the program with Ctrl-C.

### 2. Look at one line: `--explain`

`--explain` prints what syslogcef sees in each line instead of bare CEF:

```bash
grep 'Failed password' /var/log/secure | head -n 1 | syslogcef --explain
```

```text
--- line 1
raw:     <38>Nov 21 10:15:02 bastion sshd[2211]: Failed password for invalid user admin from 203.0.113.7 port 52144 ssh2
parser:  rfc3164
pattern: -
msg pattern: -
mapping: auto linux
fields:
  app = sshd
  dvcpid = 2211
  facility = 4
  host = bastion
  message_length = 71
  message_short = Failed password for invalid user admin from 203.0.113.7 port 52144 ssh2
  msg = Failed password for invalid user admin from 203.0.113.7 port 52144 ssh2
  pid = 2211
  pri = 38
  raw_kv = 
  rt = 1795256102000
  severity = 6
  source_hint = rfc3164
  timestamp = 2026-11-21T10:15:02+00:00
  ts = 2026-11-21T10:15:02+00:00
  ts_orig = Nov 21 10:15:02
cef:     CEF:0|Linux|Syslog|auto|linux.syslog|Failed password for invalid user admin from 203.0.113.7 port 52144 ssh2|2|msg=Failed password for invalid user admin from 203.0.113.7 port 52144 ssh2 shost=bastion rt=1795256102000 sproc=sshd dvcpid=2211 cs1Label=rawEvent cs1=<38>Nov 21 10:15:02 bastion sshd[2211]: Failed password for invalid user admin from 203.0.113.7 port 52144 ssh2
```

Each block shows:

| Line | Meaning |
|---|---|
| `raw` | The input line. |
| `parser` | The parser that read the header (the event's `source_hint`). |
| `pattern` | The line pattern that matched, or `-`. |
| `msg pattern` | The msg pattern that matched, or `-`. |
| `mapping` | Where the CEF mapping came from: `--mapping` (you forced one), `pattern <name>` (a pattern's `mapping` key), or `auto <name>` (a bundled mapping picked from the message content). |
| `fields` | Every field a mapping template can use, sorted by name. `raw` is left out because it is already shown. Values over 200 characters are cut and end in `...`. |
| `cef` | The CEF record that normal output would have written. |

Blocks are separated by a blank line. `--explain` writes to stdout, so it
cannot be combined with `--output`, `--send`, or `--multiprocess`.

The `fields` list is the important part. Two things stand out:

- `msg` holds the whole message, and there is no `src`, `spt` or user field.
- `app = sshd`. That is the program name from the syslog header, and it is
  how a msg pattern can be limited to OpenSSH lines.

### 3. Write a msg pattern

Create `/etc/syslogcef/patterns/sshd.json`:

```json
{
  "patterns": [
    {
      "name": "sshd_auth",
      "match": "msg",
      "app": ["sshd", "sshd-session"],
      "regex": "^(?P<outcome>Accepted|Failed) %{NOTSPACE:auth_method} for (?:invalid user )?%{USER:suser} from %{IP:src} port %{PORT:spt}"
    }
  ]
}
```

What each part does:

- `"match": "msg"` applies the regex to the message text (`Failed password
  for ...`), after syslogcef has already read the header. You do not have to
  match the timestamp, host or program name.
- `"app": ["sshd", "sshd-session"]` only tries this pattern on events whose
  program name is one of these (case does not matter). OpenSSH 9.8 and later
  log authentication from `sshd-session`, older versions from `sshd`.
- The regex, read left to right:

  | Piece | Matches | Becomes field |
  |---|---|---|
  | `^` | start of the message | |
  | `(?P<outcome>Accepted\|Failed)` | the word `Accepted` or `Failed` | `outcome` |
  | `%{NOTSPACE:auth_method}` | `password`, `publickey`, `keyboard-interactive/pam` | `auth_method` |
  | ` for ` | literal text | |
  | `(?:invalid user )?` | the words `invalid user `, if present | (none, `(?:...)` does not capture) |
  | `%{USER:suser}` | `admin`, `deploy` | `suser` |
  | ` from ` | literal text | |
  | `%{IP:src}` | `203.0.113.7` | `src` |
  | ` port ` | literal text | |
  | `%{PORT:spt}` | `52144` | `spt` |

  `%{NAME:field}` is a [shorthand](#shorthands): syslogcef replaces it with
  a tested regex for that kind of value, captured under the field name you
  give. Everything else is an ordinary Python regular expression. The `|`
  inside `(?P<outcome>...)` means "or".

- The field names are CEF extension names (`src`, `spt`, `suser`,
  `outcome`). That is a convention, not a requirement, but it makes the
  mapping in step 6 obvious. See [Choosing field names](#choosing-field-names).

### 4. Add examples

Put sample lines next to the regex. They document the pattern and let
syslogcef test it:

```json
"examples": [
  {
    "line": "<38>Nov 21 10:15:02 bastion sshd[2211]: Failed password for invalid user admin from 203.0.113.7 port 52144 ssh2",
    "expect": {"outcome": "Failed", "auth_method": "password", "suser": "admin", "src": "203.0.113.7", "spt": 52144}
  },
  {
    "line": "<38>Nov 21 10:15:09 bastion sshd[2214]: Accepted publickey for deploy from 198.51.100.4 port 40022 ssh2",
    "expect": {"outcome": "Accepted", "suser": "deploy", "src": "198.51.100.4", "spt": 40022}
  },
  {
    "line": "<38>Nov 21 10:15:01 bastion sshd[2211]: Invalid user admin from 203.0.113.7 port 52144",
    "matches": false
  }
]
```

- `line` is a complete log line, header included, exactly as it appears in
  the file. It runs through the whole pipeline, even for a msg pattern.
- `expect` lists fields that must come out with these values. Numbers may be
  written as JSON numbers (`52144`) or strings (`"52144"`); both are compared
  as text.
- `"matches": false` says this line must **not** match this pattern. Use it
  for lines that look similar but mean something else.

Copy real lines from your logs, and replace addresses and user names if the
file will be shared.

### 5. Test: `--check-patterns`

```bash
syslogcef --patterns /etc/syslogcef/patterns/sshd.json --check-patterns
```

```text
PASS sshd_auth example 1
PASS sshd_auth example 2
PASS sshd_auth example 3
3/3 examples passed
```

`--check-patterns` loads the files, runs every example of every pattern, and
exits with status 0 if all pass, 1 if any fail. An unknown key in a pattern
or example (usually a typo) also counts as a failure; see
[Unknown keys](#unknown-keys). It reads no log input, so it
cannot be combined with input paths, `--listen` or `--tail`. With no examples
in any loaded file it prints `no examples defined` and exits 0.

A failure names the example and says what was wrong. Here the second
example's `expect` was changed to `"spt": 40023`:

```text
PASS sshd_auth example 1
FAIL sshd_auth example 2: field spt: expected '40023', got '40022'
PASS sshd_auth example 3
2/3 examples passed
```

Run it whenever you change a pattern file, and in CI if your pattern files
live in a repository.

### 6. Map the fields to CEF

A captured field only reaches the CEF record if a mapping template refers to
it. Without a mapping of your own, the bundled mapping syslogcef picks
(`linux` here) knows nothing about `src` or `suser`, so they would be left
out.

Create `/etc/syslogcef/patterns/sshd-mapping.json`, in the same format as
the bundled mappings (see [Mapping Files](../README.md#mapping-files) in the
README):

```json
{
  "deviceVendor": "OpenBSD",
  "deviceProduct": "OpenSSH",
  "deviceVersion": "auto",
  "eventClassId": "sshd.%(outcome)s",
  "name": "%(message_short)s",
  "extensions": {
    "src": "%(src)s",
    "spt": "%(spt)s",
    "suser": "%(suser)s",
    "outcome": "%(outcome)s",
    "shost": "%(host)s",
    "sproc": "%(app)s",
    "dvcpid": "%(dvcpid)s",
    "cs2Label": "authMethod",
    "cs2": "%(auth_method)s",
    "cs1Label": "rawEvent",
    "cs1": "%(raw)s"
  }
}
```

The connection is simple: a regex group named `src` becomes the field `src`,
the template `%(src)s` reads that field, and the extension key it sits under
(`"src"`) is the CEF key written to the record. `auth_method` has no standard
CEF key, so it goes into the custom string `cs2` with a label.

Point the pattern at the mapping with the `mapping` key. A relative path is
resolved against the directory of the pattern file, so the two files can move
together:

```json
"mapping": "sshd-mapping.json"
```

The mapping is loaded and checked when the pattern file loads. It is used for
every event this pattern matches, and only for those; other events keep
automatic mapping selection. A `--mapping` given on the command line always
wins over a pattern's mapping.

The complete pattern file is
[examples/patterns/sshd.json](../examples/patterns/sshd.json) and the mapping
is [examples/patterns/sshd-mapping.json](../examples/patterns/sshd-mapping.json).

### 7. Check the result

```bash
head -n 1 /var/log/secure | syslogcef --patterns /etc/syslogcef/patterns/sshd.json --explain
```

```text
--- line 1
raw:     <38>Nov 21 10:15:02 bastion sshd[2211]: Failed password for invalid user admin from 203.0.113.7 port 52144 ssh2
parser:  rfc3164
pattern: -
msg pattern: sshd_auth
mapping: pattern sshd_auth
fields:
  app = sshd
  auth_method = password
  dvcpid = 2211
  facility = 4
  host = bastion
  message_length = 71
  message_short = Failed password for invalid user admin from 203.0.113.7 port 52144 ssh2
  msg = Failed password for invalid user admin from 203.0.113.7 port 52144 ssh2
  outcome = Failed
  pid = 2211
  pri = 38
  raw_kv = 
  rt = 1795256102000
  severity = 6
  source_hint = rfc3164
  spt = 52144
  src = 203.0.113.7
  suser = admin
  timestamp = 2026-11-21T10:15:02+00:00
  ts = 2026-11-21T10:15:02+00:00
  ts_orig = Nov 21 10:15:02
cef:     CEF:0|OpenBSD|OpenSSH|auto|sshd.Failed|Failed password for invalid user admin from 203.0.113.7 port 52144 ssh2|2|msg=Failed password for invalid user admin from 203.0.113.7 port 52144 ssh2 shost=bastion rt=1795256102000 src=203.0.113.7 spt=52144 suser=admin outcome=Failed sproc=sshd dvcpid=2211 cs2Label=authMethod cs2=password cs1Label=rawEvent cs1=<38>Nov 21 10:15:02 bastion sshd[2211]: Failed password for invalid user admin from 203.0.113.7 port 52144 ssh2
```

Without `--explain`, both lines convert to CEF with the captured fields:

```bash
syslogcef --patterns /etc/syslogcef/patterns/sshd.json /var/log/secure
```

```text
CEF:0|OpenBSD|OpenSSH|auto|sshd.Failed|Failed password for invalid user admin from 203.0.113.7 port 52144 ssh2|2|msg=Failed password for invalid user admin from 203.0.113.7 port 52144 ssh2 shost=bastion rt=1795256102000 src=203.0.113.7 spt=52144 suser=admin outcome=Failed sproc=sshd dvcpid=2211 cs2Label=authMethod cs2=password cs1Label=rawEvent cs1=<38>Nov 21 10:15:02 bastion sshd[2211]: Failed password for invalid user admin from 203.0.113.7 port 52144 ssh2
CEF:0|OpenBSD|OpenSSH|auto|sshd.Accepted|Accepted publickey for deploy from 198.51.100.4 port 40022 ssh2|2|msg=Accepted publickey for deploy from 198.51.100.4 port 40022 ssh2 shost=bastion rt=1795256109000 src=198.51.100.4 spt=40022 suser=deploy outcome=Accepted sproc=sshd dvcpid=2214 cs2Label=authMethod cs2=publickey cs1Label=rawEvent cs1=<38>Nov 21 10:15:09 bastion sshd[2214]: Accepted publickey for deploy from 198.51.100.4 port 40022 ssh2
```

`--stats` now has a "by msg pattern" section, which shows how many lines the
pattern picked fields out of:

```bash
syslogcef --stats --patterns /etc/syslogcef/patterns/sshd.json /var/log/secure > /dev/null
```

```text
syslogcef: 2 lines
  by parser:
    rfc3164  2
  by msg pattern:
    sshd_auth  2
  unmatched (adaptive or unknown): 0
```

Add `--validate` while you are developing. It warns when a value does not fit
its CEF key, for example a non-numeric `spt` or an IPv6 address in `src`.

### 8. Use it in the service

The packaged service passes `EXTRA_ARGS` to syslogcef unchanged. Add the
pattern file there, in `/etc/syslogcef/syslogcef.conf` or in an instance file
under `/etc/syslogcef/conf.d/`:

```bash
INPUT_FILE=/var/log/secure
OUTPUT_FILE=/var/log/syslogcef/secure.cef
EXTRA_ARGS=--patterns /etc/syslogcef/patterns/sshd.json
```

`--patterns` can be repeated to load several files:

```bash
EXTRA_ARGS=--patterns /etc/syslogcef/patterns/sshd.json --patterns /etc/syslogcef/patterns/acme.json
```

Then restart the service (`systemctl restart syslogcef`, or
`syslogcef@NAME`). Pattern files are checked at startup: a broken file stops
the service from starting, with the reason in `journalctl -u syslogcef`,
instead of producing bad records. Run `--check-patterns` before restarting to
catch problems early.

## Line patterns and msg patterns

There are two kinds of pattern, chosen with the `match` key.

| | Line pattern (`"match": "line"`, the default) | Msg pattern (`"match": "msg"`) |
|---|---|---|
| Applied to | the whole raw line | the message text, after the header has been parsed |
| Use when | the header format is not recognized (`--stats` shows the lines as unmatched, or `--explain` shows `parser: adaptive` or `unknown` or a wrong host/program/time) | the header is parsed correctly but the message carries values you want as fields |
| Regex is matched with | `re.match`: it must match from the start of the line | `re.search`: it may match anywhere in the message, so anchor it with `^` |
| Fills the envelope | yes: groups `pri`, `host`, `app`, `pid`, `msgid`, `msg`, `ts` | no: those group names are not allowed |
| Other named groups | become fields | become fields |
| Keys only for this kind | `timestamp_format`, `priority` | `app` |
| Shows up as | `pattern:` in `--explain`, `custom:<name>` under "by parser" in `--stats` | `msg pattern:` in `--explain`, "by msg pattern" in `--stats` |

Most of the time you want a msg pattern. Nearly every device sends a header
syslogcef already understands, and it is much easier to write a regex for
`Failed password for admin from 203.0.113.7` than for the whole line.

### How the two kinds run

For each input line:

1. Line patterns with `"priority": "before"` are tried, in load order.
2. The built-in parsers are tried.
3. Line patterns with `"priority": "after"` (the default) are tried, in load
   order.
4. The adaptive fallback handles anything left.
5. After any successful parse (including a forced `--mode`), msg patterns
   are tried against the message, in load order. The first one that matches
   wins; the rest are skipped. A msg pattern with an `app` list is skipped
   for events whose program name is not in the list.

The two kinds combine: a line pattern can read an unknown header, and a msg
pattern can then pick fields out of the message. If both capture a field
with the same name, the msg pattern's value is used.

Pattern names are also accepted by `--mode`, which forces that parser for
every line, as with the built-in parser names.

### A line pattern

[examples/patterns/acme-line.json](../examples/patterns/acme-line.json)
reads an invented firewall format whose header no built-in parser knows:

```text
ACME 2026-11-21T10:15:02Z fw01 acmefw[311]: DENY tcp 10.1.2.3:51514 -> 192.0.2.10:443 rule=17
```

```json
{
  "patterns": [
    {
      "name": "acme_fw",
      "regex": "^ACME %{TIMESTAMP_ISO8601:ts} %{HOSTNAME:host} %{WORD:app}\\[%{INT:pid}\\]: (?P<msg>%{WORD:act} %{WORD:proto} %{IPV4:src}:%{PORT:spt} -> %{IPV4:dst}:%{PORT:dpt}.*)$",
      "timestamp_format": "iso8601",
      "priority": "after",
      "mapping": "acme-mapping.json",
      "examples": [
        {
          "line": "ACME 2026-11-21T10:15:02Z fw01 acmefw[311]: DENY tcp 10.1.2.3:51514 -> 192.0.2.10:443 rule=17",
          "expect": {"host": "fw01", "app": "acmefw", "pid": 311, "act": "DENY", "src": "10.1.2.3", "dpt": 443, "rule": 17}
        }
      ]
    }
  ]
}
```

Points to notice:

- `ts`, `host`, `app`, `pid` and `msg` fill the event envelope, the same
  fields a built-in parser fills. The `ts` group needs `timestamp_format`.
- `act`, `proto`, `src`, `spt`, `dst` and `dpt` are extra captures. They
  become fields, just like the groups of a msg pattern.
- The extra captures sit inside the `msg` group. Groups may be nested, so the
  message text and the values inside it are captured in one pass.
- In JSON, a regex backslash is written twice: `\\[` in the file is the
  regex `\[`, a literal `[`.
- `rule=17` is not captured, yet the example expects `rule`. syslogcef still
  reads `key=value` pairs from the message text, as it does for every event.
- Without a `msg` group, the message is the whole line.

## Reference

### Pattern file layout

A pattern file is a JSON object with one key, `patterns`, holding a non-empty
list of pattern objects:

```json
{
  "patterns": [
    { "name": "first_pattern", "regex": "..." },
    { "name": "second_pattern", "regex": "...", "match": "msg" }
  ]
}
```

Patterns are tried in the order they appear, and files in the order they are
given on the command line. Put specific patterns before general ones.

### Pattern keys

| Key | Type | Kind | Required | Meaning |
|---|---|---|---|---|
| `name` | string | both | yes | Unique name, used in `--explain`, `--stats`, `--check-patterns` output and as a `--mode` value. Must not be a built-in parser name (`rfc3164`, `rfc5424`, `rsyslog_json`, `rsyslog_file`, `journald_json`, `journald_short`, `journald_iso`, `cisco_seq`, `iso_syslog`, `kv`) or a name already loaded. |
| `regex` | string | both | yes | Python regular expression. May contain [shorthands](#shorthands). Named groups become fields. |
| `match` | `"line"` or `"msg"` | both | no, default `"line"` | Whether the regex is applied to the whole raw line or to the parsed message. |
| `timestamp_format` | string | line only | only with a `ts` group | How to read the `ts` group: a strptime format such as `"%Y-%m-%d %H:%M:%S"`, `"iso8601"`, or `"epoch"` (seconds since 1970). Required when the regex has a `ts` group, and not allowed without one. Formats without a year get the same year inference as the built-in parsers. A timestamp that fails to parse never drops the line. |
| `priority` | `"before"` or `"after"` | line only | no, default `"after"` | `"before"`: tried ahead of the built-in parsers, so it overrides them. `"after"`: tried after the built-in parsers, ahead of the adaptive fallback. |
| `app` | string or list of strings | msg only | no | Only apply the pattern when the event's program name (the `app` field) equals one of these values, ignoring case. Without it, the pattern is tried on every event. |
| `mapping` | string | both | no | CEF mapping for events this pattern matches. Either a bundled mapping name (`cisco_asa`, `cisco_ios`, `f5`, `fortinet`, `linux`, `sophos`, `vmware`) or a path to a mapping JSON file. A relative path is resolved against the pattern file's directory. Loaded and checked when the pattern file loads. |
| `examples` | list of objects | both | no | Sample lines checked by `--check-patterns`. See [Examples](#examples). |
| `description` | string | both | no | Free text for people reading the file, such as where the lines come from. syslogcef does not use it. |

Any other key does not stop the file from loading: syslogcef ignores it and
logs a warning that names the file, the pattern and the key. The key is
usually a typo such as `"exmaples"`, which would otherwise silently drop
your examples, so `--check-patterns` reports every such key as a failure
(see [Unknown keys](#unknown-keys)).

### Named groups and fields

| Group name | In a line pattern | In a msg pattern |
|---|---|---|
| `pri`, `host`, `app`, `pid`, `msgid`, `msg`, `ts` | fill the event envelope | not allowed |
| a [reserved name](#reserved-names) | not allowed | not allowed |
| anything else | becomes a field | becomes a field |

A group that did not take part in the match (for example inside an optional
`(...)?` that was skipped) produces no field, so the mapping simply leaves
that extension out.

### Reserved names

These names are computed by syslogcef for every event, so a pattern cannot
capture them:

`facility`, `severity`, `timestamp`, `ts_orig`, `source_hint`, `raw`,
`raw_kv`, `rt`, `message_length`, `message_short`, `dvcpid`

They are all available to mapping templates. `facility` and `severity` come
from the `pri` value (`severity` can also come from the message when there
is no PRI), `timestamp`, `ts_orig` and `rt` from `ts`, `dvcpid`
from `pid`, `message_short` and `message_length` from `msg`.

### How captured fields reach the CEF record

1. A named group, for example `%{IP:src}`, captures `203.0.113.7` as the
   field `src`.
2. The field joins the event's other fields: the envelope (`host`, `app`,
   ...), `key=value` pairs read from the message, and the reserved fields
   above. If the message itself contains `src=10.9.9.9`, your captured value
   wins.
3. Field names are normalized the same way as `key=value` pairs. A capture
   named after a known alias also makes the canonical CEF name available:
   `src_ip` also gives `src`, `dstport` gives `dpt`, `user` gives `suser`.
   The original name stays available too.
4. A mapping template reads the field by name: `"src": "%(src)s"` in the
   mapping's `extensions` writes `src=203.0.113.7` to the record.
5. A template whose field is missing renders empty, and an empty extension is
   left out of the record. A header template that renders empty falls back to
   the default for that header field.

`--explain` shows the full field list for any line, which is the quickest way
to see what a template can use.

### Choosing field names

Name your groups after the CEF extension key the value belongs in. The
mapping then reads `"src": "%(src)s"`, and anyone can see what goes where.
[docs/cef_fields.md](cef_fields.md) lists every CEF key with its type and
maximum length. The keys most patterns need:

| Value | CEF key | Type |
|---|---|---|
| source / destination IPv4 address | `src` / `dst` | IPv4 address |
| source / destination port | `spt` / `dpt` | Integer |
| source / destination host name | `shost` / `dhost` | String |
| user who did something / user acted on | `suser` / `duser` | String |
| action the device took (allow, deny, drop) | `act` | String (63) |
| result (success, failure) | `outcome` | String (63) |
| transport protocol (tcp, udp) | `proto` | String (31) |
| URL | `request` | String |
| file name | `fname` | String |
| source / destination MAC address | `smac` / `dmac` | MAC address |
| category | `cat` | String |
| reason | `reason` | String |

For a value with no CEF key, capture it under a descriptive name and put it in
a custom field with a label, as the sshd example does with `auth_method`:

```json
"cs2Label": "authMethod",
"cs2": "%(auth_method)s"
```

`cs1` to `cs6` hold strings, `cn1` to `cn3` numbers. The bundled mappings
already use `cs1` for the raw line, so start your own at `cs2`.

Be careful with:

- `app`: in CEF, `app=` means the application protocol (HTTP, SSH). The
  syslog program name is the field `app`, which belongs in CEF `sproc=`.
- IPv6 addresses: `--validate` accepts only IPv4 in `src` and `dst`. If a
  field can hold IPv6, see the IPv6 custom fields (`c6a1`, `c6a3`, `c6a4`) in
  [docs/cef_fields.md](cef_fields.md).
- Values the mapping cannot change: a template copies text, it cannot turn
  `Failed` into `failure`. If your SIEM content expects specific values, match
  them in the regex where you can, or adjust the SIEM side.

### Mappings per pattern

A pattern's `mapping` is used for every event it matched, and the order of
precedence is:

1. `--mapping` on the command line, always.
2. The `mapping` of the msg pattern that matched.
3. The `mapping` of the line pattern that matched.
4. Automatic selection of a bundled mapping from the message content.

The mapping file format is described under
[Mapping Files](../README.md#mapping-files) in the README:
header keys, `severity_map`, and `extensions`, with `%(field)s` templates.
Like `--mapping` files, a pattern's mapping is checked when it loads:
malformed templates, bad extension keys and bad severity maps are reported
immediately.

The mapping replaces the bundled one, it does not add to it. Copy the
`shost`, `sproc`, `dvcpid` and `cs1` lines from `syslogcef/mappings/linux.json`
if you want to keep them. `msg`, `shost`, `rt` and the `cs1` raw line are
added by default unless your mapping sets them.

### Shorthands

Write `%{NAME}` to insert a ready-made regex, or `%{NAME:field}` to capture
it as a field. `NAME` is upper case. `%{NAME}` alone matches without
capturing. Text that is not a shorthand is left untouched, and an unknown
name is an error that lists the known ones.

| Shorthand | Matches | Example |
|---|---|---|
| `IPV4` | dotted IPv4 address, each part 0-255 | `203.0.113.7` |
| `IPV6` | IPv6 address, including `::` and IPv4-suffixed forms | `2001:db8::7` |
| `IP` | IPv4 or IPv6 (IPv4 is tried first) | either of the above |
| `INT` | whole number, optional sign | `-5`, `311` |
| `NUMBER` | number with optional decimals and sign | `0.25`, `-3` |
| `PORT` | 1 to 5 digits | `52144` |
| `WORD` | letters, digits and underscore | `DENY`, `tcp` |
| `NOTSPACE` | anything up to the next space | `keyboard-interactive/pam` |
| `DATA` | anything, as little as possible | |
| `GREEDYDATA` | anything, as much as possible | rest of the line |
| `HOSTNAME` | host name or FQDN | `fw01.example.net` |
| `USER` | letters, digits, `.`, `_`, `@`, `-` | `j.doe@corp` |
| `MAC` | MAC address with `:` or `-` | `00:1a:2b:3c:4d:5e` |
| `SYSLOGTIMESTAMP` | BSD syslog time | `Nov 21 10:15:02`, `Nov  1 10:15:02` |
| `TIMESTAMP_ISO8601` | ISO 8601 date and time, optional fraction and zone | `2026-11-21T10:15:02Z`, `2026-11-21 10:15:07.250+01:00` |
| `QUOTEDSTRING` | double-quoted text, with `\"` escapes, quotes included | `"two words"` |
| `PATH` | Unix path | `/var/log/secure` |
| `LOGLEVEL` | `emerg`, `alert`, `crit`, `critical`, `err`, `error`, `warn`, `warning`, `notice`, `info`, `debug`, any case | `WARNING` |

The exact regexes:

| Shorthand | Regex |
|---|---|
| `IPV4` | `(?:25[0-5]\|2[0-4]\d\|1\d\d\|[1-9]?\d)(?:\.(?:25[0-5]\|2[0-4]\d\|1\d\d\|[1-9]?\d)){3}` |
| `IPV6` | `(?:[0-9A-Fa-f]{0,4}:){2,7}(?:[0-9A-Fa-f]{1,4}\|(?:\d{1,3}\.){3}\d{1,3})?` |
| `IP` | `(?:` IPV4 `\|` IPV6 `)` |
| `INT` | `[+-]?\d+` |
| `NUMBER` | `[+-]?\d+(?:\.\d+)?` |
| `PORT` | `\d{1,5}` |
| `WORD` | `\w+` |
| `NOTSPACE` | `\S+` |
| `DATA` | `.*?` |
| `GREEDYDATA` | `.*` |
| `HOSTNAME` | `[A-Za-z0-9][A-Za-z0-9-]{0,62}(?:\.[A-Za-z0-9-]{1,63})*\.?` |
| `USER` | `[A-Za-z0-9._@-]+` |
| `MAC` | `(?:[0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}` |
| `SYSLOGTIMESTAMP` | `[A-Z][a-z]{2} {1,2}\d{1,2} \d{2}:\d{2}:\d{2}` |
| `TIMESTAMP_ISO8601` | `\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z\|[+-]\d{2}:?\d{2})?` |
| `QUOTEDSTRING` | `"(?:[^"\\]\|\\.)*"` |
| `PATH` | `(?:/[^/\s]*)+` |
| `LOGLEVEL` | `(?i:emerg\|alert\|crit(?:ical)?\|err(?:or)?\|warn(?:ing)?\|notice\|info\|debug)` |

(If you read this file as plain text: `\|` in the tables above is Markdown
escaping. The regexes contain a plain `|`.)

`%{NAME}` becomes `(?:regex)` and `%{NAME:field}` becomes
`(?P<field>regex)`. The same reserved-name and envelope rules apply to
`field` as to any named group. Shorthands do not check meaning: `PORT`
accepts `99999` and `IPV6` also matches a time such as `10:15:02`, so put
literal text around them (`from %{IP:src} port`) rather than relying on the
shorthand alone.

### Examples

Each entry in `examples` is an object:

| Key | Type | Required | Meaning |
|---|---|---|---|
| `line` | string | yes | A complete input line, header included. |
| `expect` | object | no | Field name to expected value (string or number). |
| `matches` | boolean | no, default `true` | Whether this pattern should match the line. |

Any other key in an example (for instance `"expcet"`) is ignored with a
warning, like an unknown pattern key. `--check-patterns` runs each `line` through the
same pipeline as normal conversion, with automatic parser detection (as if no
`--mode` were given), and then:

- with `matches` true (the default), the example passes when this pattern is
  the line pattern (for a line pattern) or the msg pattern (for a msg
  pattern) that matched the line, and every `expect` field exists with
  exactly the expected value. Values are compared as text, so `52144` and
  `"52144"` are the same.
- with `"matches": false`, the example passes when this pattern did **not**
  match the line.

`expect` can check any field `--explain` lists, not only your captures:
`host`, `app`, `severity`, `ts` and so on. It checks fields, not the CEF
record, so the mapping does not affect it.

An example can fail because another pattern matched first. Patterns are tried
in load order and the first match wins, so a general pattern loaded before a
specific one takes its lines. The failure then says this pattern did not
match; `--explain` on the example line shows which one did.

### Error messages

Pattern files are checked when they load: at startup, and for
`--check-patterns`. Any problem stops syslogcef with exit status 2, a usage
summary, and a message that names the file and the pattern. For example, with
`%{IPADDR:src}` in the regex instead of `%{IP:src}`:

```bash
cd /etc/syslogcef/patterns
syslogcef --patterns sshd.json --check-patterns
```

```text
usage: syslogcef [-h] [-o OUTPUT] [-a] [--mode MODE] [--mapping MAPPING]
                 [--patterns FILE] [--tail] [--check-patterns]
                 [--listen PROTO:PORT] [--send URL] [--eps EPS]
                 [--multiprocess] [--pool-size POOL_SIZE] [--validate]
                 [--strict] [--explain] [--stats] [--log-level LOG_LEVEL]
                 [--version]
                 [paths ...]
syslogcef: error: sshd.json: pattern 'sshd_auth': unknown shorthand %{IPADDR}; known: DATA, GREEDYDATA, HOSTNAME, INT, IP, IPV4, IPV6, LOGLEVEL, MAC, NOTSPACE, NUMBER, PATH, PORT, QUOTEDSTRING, SYSLOGTIMESTAMP, TIMESTAMP_ISO8601, USER, WORD
```

The message text contains one of these phrases:

| Message contains | Cause and fix |
|---|---|
| `cannot read pattern file` | The path is wrong or not readable by the service user. |
| `invalid JSON in pattern file` | A JSON syntax error; the message gives the line and column. A common cause is a single backslash: in the file, write `\\d`, not `\d`. |
| `expected an object with a non-empty 'patterns' list` | The top level must be `{"patterns": [ ... ]}` with at least one pattern. |
| `missing 'name'`, `missing 'regex'` | Every pattern needs both. |
| `shadows a built-in parser name` | Pick a name that is not `rfc3164`, `kv`, or another built-in parser name. |
| `duplicate name` | Two patterns, in the same or different files, have the same name. |
| `invalid regex` | Python could not compile the regex (after shorthand expansion); the message says why. |
| `unknown shorthand %{NAME}; known: ...` | The shorthand name is misspelled or not in the [table](#shorthands). Names are upper case. |
| `a 'ts' group requires 'timestamp_format'` | Add `timestamp_format`: a strptime format, `iso8601`, or `epoch`. |
| `'timestamp_format' given but the regex has no 'ts' group` | Remove `timestamp_format`, or add the `ts` group. |
| `'timestamp_format' must be a strptime format, 'iso8601', or 'epoch'` | The format has an unsupported `%` code. |
| `'priority' must be 'before' or 'after'` | Fix the value. |

These checks also stop the load. Their messages name the file, the pattern
and the offending key or group:

| Check | Cause and fix |
|---|---|
| Reserved name | A group is named `severity`, `raw`, `rt` or another [reserved name](#reserved-names). Rename it. |
| Envelope group in a msg pattern | A msg pattern has a group named `pri`, `host`, `app`, `pid`, `msgid`, `msg` or `ts`. Rename it, or use a line pattern. |
| `timestamp_format` or `priority` on a msg pattern | These only apply to line patterns. Remove them. |
| `app` key on a line pattern | The `app` filter only applies to msg patterns. To read the program name in a line pattern, capture it with an `(?P<app>...)` group. |
| Mapping | The `mapping` value is not a bundled mapping name, the file cannot be read, or the mapping fails the same checks as a `--mapping` file (templates, extension keys, severity map). |
| Example structure | An example is not an object, has no `line`, or has an `expect` that is not an object or a `matches` that is not true or false. |
| `'description' must be a string` | The `description` value is a number, list or object. |

### Unknown keys

A key that this reference does not list, in a pattern or in an example, does
not stop the load. syslogcef ignores the key, keeps running, and logs a
warning to stderr that names the file, the pattern and the key. Pattern files
written for a newer syslogcef therefore still load on an older one.

Most unknown keys are typos, and a typo can quietly disable a feature: a
pattern with `"exmaples"` instead of `"examples"` has no examples at all. So
`--check-patterns` turns each unknown key into a failure, and exits 1:

```bash
syslogcef --patterns sshd.json --check-patterns
```

```text
WARNING:syslogcef.custom:sshd.json: pattern 'sshd_auth': unknown key 'exmaples' (ignored)
FAIL sshd_auth config: unknown key 'exmaples'
no examples defined; 1 config problem
```

The first line is the warning on stderr; the rest is the report on stdout.
An unknown key inside an example is reported as, for instance,
`FAIL sshd_auth config: unknown key 'expcet' in example 2`. To leave a note
in the file, use the `description` key, which is never reported.

## Keeping regexes fast (ReDoS)

Pattern regexes run on every line that reaches them, and the lines come from
the network or from devices you do not control. A badly shaped regex can take
seconds or minutes on a single crafted line ("catastrophic backtracking", or
ReDoS), and syslogcef has no time limit on a regex. While it is stuck, the
pipeline stops.

Rules that keep you safe:

- **Never nest repetition.** `(\w+\s?)+`, `(a|aa)*`, `(.*,)*` and similar
  can take exponential time on a line that almost matches. Match one token
  at a time instead: `%{WORD} %{WORD} %{WORD}`.
- **Anchor.** Start line patterns and msg patterns with `^`. A msg pattern
  without `^` is retried at every position in the message.
- **Prefer specific tokens over "anything".** `%{NOTSPACE}`, `%{WORD}`,
  `%{IP}` and `[^,]*` stop at a clear boundary. `%{DATA}` and `%{GREEDYDATA}`
  (`.*?` and `.*`) are fine once, at the end or before a distinctive literal,
  but several of them in a row make the engine try many ways to split the
  text.
- **Use literal text as landmarks.** `from %{IP:src} port %{PORT:spt}` is
  fast because ` from ` and ` port ` rule out most positions immediately.
- **Limit msg patterns with `app`.** Without it, a msg pattern is tried on
  every event of every device.
- **Test with a bad line.** Add a long `"matches": false` example that almost
  matches (right prefix, wrong ending) and time `--check-patterns`. It should
  finish instantly.

The shorthands themselves contain no nested unbounded repetition.

## Troubleshooting

**The pattern never matches.**
Run the line through `--explain` with your `--patterns`.

- `parser:` is not what you expected: for a msg pattern, check that the
  header was parsed at all (an `adaptive` or `unknown` parser may have left
  part of the header in `msg`).
- `msg pattern: -` on a parsed line: compare your regex with the `msg` value
  shown, not with the raw line. The message starts after `program[pid]: `.
- The `app` filter does not match: compare it with the `app` field `--explain`
  shows. OpenSSH 9.8 and later log as `sshd-session`. Some devices put the
  program name in a different place, leaving `app` empty.
- Another pattern matched first: `--explain` names it. Move the specific
  pattern earlier, or tighten the general one.
- A line pattern loses to a built-in parser: give it `"priority": "before"`.

**The pattern matches, but a field is missing from the CEF record.**
`--explain` shows whether the field exists. If it is in `fields:` but not in
`cef:`, no mapping template refers to it: check `mapping:` in the `--explain`
block to see which mapping was used, then add the extension to that mapping.
If `mapping:` says `auto ...`, the pattern has no `mapping` key.

**A field has the wrong value.**
Usually a shorthand matched more or less than intended. `DATA` stops as early
as it can, `GREEDYDATA` runs to the end. Put literal text after a capture to
say where it ends.

**Fields from the message's own `key=value` text disappear.**
A capture with the same name replaces the `key=value` value. Rename the
capture.

**JSON escapes.**
Every backslash in a regex is doubled in JSON: `\d` is written `"\\d"`, `\[`
is `"\\["`, and a literal backslash `\\` is `"\\\\"`. Shorthands avoid most
backslashes.

**Testing a regex alone.**
Python's `re` is the engine, so a quick check works without syslogcef:

```bash
python3 -c 'import re; print(re.search(r"^(?P<outcome>Accepted|Failed) (?P<auth_method>\S+) for", "Failed password for admin").groupdict())'
```

```text
{'outcome': 'Failed', 'auth_method': 'password'}
```

(Shorthands are expanded by syslogcef, so write the plain regex in such a
test.)

**Python API.**
`syslogcef.load_patterns(path)` loads the same files from Python, and
`syslogcef.register_parser(name, fn)` registers a parser function for cases a
regex cannot express. See [Custom Parsers](../README.md#custom-parsers) in
the README.
