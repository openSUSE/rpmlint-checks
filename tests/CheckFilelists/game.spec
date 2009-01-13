Name:		game
Version:	0
Release:	0
Group:		Foo
Summary:	Bar
License:	GPL
BuildRoot:	%_tmppath/%name-%version-build

%description
%_target
%_target_cpu

%install
install -D -m 755 /bin/sh %buildroot/usr/games/foo
install -D -m 755 /bin/sh %buildroot/usr/games/lib/blub

%clean
rm -rf %buildroot

%files
/usr/games/*
