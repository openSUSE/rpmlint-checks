Name:		systemd-bad
Version:	0
Release:	0
Group:          Development/Tools/Building
Summary:	Bar
License:	GPL
BuildRoot:	%_tmppath/%name-%version-build

%description
%_target
%_target_cpu

%install
install -D -m 644 /dev/null %buildroot/usr/lib/systemd/system/mysql.service

%clean
rm -rf %buildroot

%files
%defattr(-,root,root)
/usr/lib/systemd/system/mysql.service
