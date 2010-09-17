Name:		cvs-bad
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
install -D -m 644 /etc/motd %buildroot/usr/lib/foo/.cvsignore
install -D -m 644 /etc/motd %buildroot/usr/lib/foo/CVS/foo
install -D -m 644 /etc/motd %buildroot/usr/lib/foo/bla,v
install -D -m 644 /etc/motd %buildroot/usr/lib/foo/RCS/asd

%clean
rm -rf %buildroot

%files
%defattr(-,root,root)
/usr/lib/*

%changelog
