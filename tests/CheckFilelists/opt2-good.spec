Name:		opt2-good
Version:	0
Release:	0
Group:		Foo
Summary:	Bar
License:	GPL
BuildRoot:	%_tmppath/%name-%version-build
Vendor:         xxSUSE yy

%description
%_target
%_target_cpu

%install
install -D -m 644 /etc/motd %buildroot/opt/novell/blah
install -D -m 644 /etc/motd %buildroot/opt/suse/blub

%clean
rm -rf %buildroot

%files
/opt/*
