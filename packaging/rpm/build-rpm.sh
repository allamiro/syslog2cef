#!/usr/bin/env bash
# Build the RPM and SRPM from this checkout, then lint them.
#
# Used by CI (every pull request) and by the release workflow, so a spec
# or %check problem fails the pull request instead of the release. Run it
# from the repository root inside a Fedora container that has rpm-build,
# rpmdevtools, rpmlint, python3-build and pyproject-rpm-macros installed.
# Built packages are copied to ./rpms.
set -euo pipefail

spec=packaging/rpm/syslog2cef.spec
topdir="$HOME/rpmbuild"

rm -rf dist rpms
python3 -m build --sdist
rpmdev-setuptree
cp dist/syslog2cef-*.tar.gz "$topdir/SOURCES/"
for source in syslogcef.service syslogcef@.service syslogcef.conf \
              syslogcef-instance.conf syslogcef.logrotate \
              syslogcef.sysusers syslogcef.1; do
    cp "packaging/rpm/$source" "$topdir/SOURCES/"
done

# %pyproject_buildrequires reveals build dependencies in rounds (the build
# backend first, then the test extra), so install and retry until rpmbuild
# stops asking for more.
for _ in 1 2 3 4 5; do
    rm -f "$topdir"/SRPMS/*.buildreqs.nosrc.rpm
    rpmbuild -br "$spec" >/dev/null 2>&1 || true
    if ! ls "$topdir"/SRPMS/*.buildreqs.nosrc.rpm >/dev/null 2>&1; then
        break
    fi
    dnf builddep -y "$topdir"/SRPMS/*.buildreqs.nosrc.rpm
done
rm -f "$topdir"/SRPMS/*.buildreqs.nosrc.rpm

rpmbuild -ba "$spec"
mkdir -p rpms
cp "$topdir"/RPMS/noarch/syslog2cef-*.rpm "$topdir"/SRPMS/syslog2cef-*.src.rpm rpms/

# --strict turns warnings into failures; known false positives are
# filtered in the rpmlintrc (the same file a Fedora reviewer uses).
rpmlint --strict -r packaging/rpm/syslog2cef.rpmlintrc "$spec" rpms/*.rpm
