# RPM Packaging

This directory contains everything needed to build the syslog2cef RPM:

- `syslog2cef.spec` — the spec file (noarch, built from the PyPI sdist
  `syslog2cef-X.Y.Z.tar.gz`).
- `syslogcef.service` / `syslogcef@.service` — systemd units that follow
  the configured input file and append CEF output.
- `syslogcef.conf` / `syslogcef-instance.conf` — environment files
  installed under `/etc/syslogcef/` (marked `%config(noreplace)`).
- `syslogcef.logrotate`, `syslogcef.sysusers`, `syslogcef.1` — logrotate
  snippet, sysusers.d entry, and man page.
- `rpkg.conf` / `rpkg.macros` — used only when rpkg builds the SRPM from a
  git checkout (the COPR project); see below.

## Building Locally

On Fedora or an Enterprise Linux 9+ system:

```bash
sudo dnf install rpm-build rpmdevtools python3-devel python3-build \
  pyproject-rpm-macros systemd-rpm-macros
rpmdev-setuptree

# From a repository checkout
python3 -m build --sdist
cp dist/syslog2cef-*.tar.gz ~/rpmbuild/SOURCES/
cp packaging/rpm/syslogcef.service packaging/rpm/syslogcef@.service \
   packaging/rpm/syslogcef.conf packaging/rpm/syslogcef-instance.conf \
   packaging/rpm/syslogcef.logrotate packaging/rpm/syslogcef.sysusers \
   packaging/rpm/syslogcef.1 ~/rpmbuild/SOURCES/
rpmbuild -ba packaging/rpm/syslog2cef.spec
```

The built package appears under `~/rpmbuild/RPMS/noarch/`.

## Building from Git with rpkg (what COPR does)

The [COPR project](https://copr.fedorainfracloud.org/coprs/allamiro/syslogcef/)
rebuilds the package on every push to `main`, using rpkg with this
directory as the package directory. Because that happens before a new
version reaches PyPI (and for commits that never do), `rpkg.macros`
provides the `syslog2cef_git_sdist` macro, invoked from a comment line in
the spec, which generates `syslog2cef-X.Y.Z.tar.gz` from the git tree at
`HEAD`. rpm only downloads sources that are missing, so the build never
contacts PyPI. Outside rpkg the line is an ordinary comment and the spec
builds from the PyPI sdist as above. The macro fails the build if the spec
`Version:` and the `pyproject.toml` version disagree, so bump both together.

To reproduce a COPR build locally:

```bash
sudo dnf install rpkg
cd packaging/rpm
rpkg srpm --outdir /tmp/out          # SRPM with the tarball built from git
rpmbuild --rebuild /tmp/out/syslogcef-*.src.rpm
```

## Signing the RPM

Generate or import a GPG key, then configure rpm to use it:

```bash
gpg --full-generate-key   # or: gpg --import your-key.asc
cat >> ~/.rpmmacros <<'EOF'
%_signature gpg
%_gpg_name  Your Name <you@example.com>
EOF

rpmsign --addsign ~/rpmbuild/RPMS/noarch/syslog2cef-*.noarch.rpm
```

Consumers verify with:

```bash
rpm --import your-public-key.asc
rpm --checksig syslog2cef-*.noarch.rpm
```

The release workflow signs automatically when the `GPG_PRIVATE_KEY` and
`GPG_PASSPHRASE` repository secrets are configured; see
[RELEASING.md](../../RELEASING.md).

## Installing and Running the Service

```bash
sudo dnf install syslog2cef-*.noarch.rpm
sudo vi /etc/syslogcef/syslogcef.conf   # set INPUT_FILE / OUTPUT_FILE
sudo systemctl enable --now syslogcef
journalctl -u syslogcef -f
```
