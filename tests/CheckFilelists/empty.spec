Name:		empty
Version:	0
Release:	0
Group:         Development/Tools/Building
Summary:	Bar
License:	GPL
BuildRoot:	%_tmppath/%name-%version-build

%description
%_target
%_target_cpu

%clean
rm -rf %buildroot

%files
%defattr(-,root,root)
