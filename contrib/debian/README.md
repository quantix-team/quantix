
Debian
====================
This directory contains files used to package quantixd/quantix-qt
for Debian-based Linux systems. If you compile quantixd/quantix-qt yourself, there are some useful files here.

## quantix: URI support ##


quantix-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install quantix-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your quantix-qt binary to `/usr/bin`
and the `../../share/pixmaps/quantix128.png` to `/usr/share/pixmaps`

quantix-qt.protocol (KDE)

