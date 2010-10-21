Name:		usr-src-2-bad
Version:	0
Release:	0
Group:         Development/Tools/Building
Summary:	Bar
License:	GPL
BuildRoot:	%_tmppath/%name-%version-build

%description
%_target
%_target_cpu

%install
install -D -m 644 /etc/motd %buildroot/usr/src/foo/test

%clean
rm -rf %buildroot

%files
%defattr(-,root,root)
/usr/src/*
