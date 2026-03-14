

                    GNU Privacy Guard for Windows
                   ===============================

This is GnuPG for Windows, version 2.5.17.

Content:

     1. Important notes
     2. Changes
     3. GnuPG README file
     4. Package versions
     5. Legal notices


1. Important Notes
==================

This is the core part of the GnuPG system as used by several other
frontend programs.  This installer does not provide any graphical
frontend and thus almost everything needs to be done on the command
line.  However, a small native Windows GUI tool is included which is
used by GnuPG to ask for passphrases.  It provides only the basic
functionality and is installed under the name "pinentry-basic.exe".
Other software using this core component may install a different
version of such a tool under the name "pinentry.exe" or configure the
gpg-agent to use that version.

See https://gnupg.org for latest news.  HowTo documents and manuals
can be found there but some have also been installed on your machine.

Development and maintenance of GnuPG is mostly financed by donations;
please see https://gnupg.org/donate/ for details.


2. Record of Changes
====================

This is a list of changes to the GnuPG core for this and the previous
release.

Noteworthy changes in version 2.5.17 (2026-01-27)
-------------------------------------------------

  * agent: Fix stack buffer overflow when using gpgsm and KEM.  This
    was introduced with 2.5.13; see the advisory.  [T8044]

  * tpm: Fix possible buffer overflow in PKDECRYPT.  [T8045]

  * gpg: Fix possible NULL-deref with overlong signature packets.
    [T8049]

  * gpg: New export-option "keep-expired-subkeys".  [T7990]

  * gpgsm: Make multiple search patterns work with keyboxd.  [T8026]

  * agent: Add accelerator keys for "Wrong" and "Correct".  [T8055]

  * dirmngr: Help detection of bad keyserver configurations.  [T7730]

  Release-info: https://dev.gnupg.org/T7996


Noteworthy changes in version 2.5.16 (2025-12-30)
-------------------------------------------------

  * gpg: Fix a regression in 2.5.15 which created new keys with just
    the fallback preferences.  [T7909]

  Release-info: https://dev.gnupg.org/T7995




3. GnuPG README File
====================

Below is the README file as distributed with the GnuPG source.

                       The GNU Privacy Guard
                      =======================
                           Version 2.5

          Copyright 1997-2019 Werner Koch
          Copyright 1998-2021 Free Software Foundation, Inc.
          Copyright 2003-2025 g10 Code GmbH


* INTRODUCTION

  GnuPG is a complete and free implementation of the OpenPGP standard
  as defined by RFC4880 (also known as PGP).  GnuPG enables encryption
  and signing of data and communication, and features a versatile key
  management system as well as access modules for public key
  directories.

  GnuPG, also known as GPG, is a command line tool with features for
  easy integration with other applications.  A wealth of frontend
  applications and libraries are available that make use of GnuPG.
  Starting with version 2 GnuPG provides support for S/MIME and Secure
  Shell in addition to OpenPGP.

  GnuPG is Free Software (meaning that it respects your freedom). It
  can be freely used, modified and distributed under the terms of the
  GNU General Public License.

  Note that this is considered the stable version of GnuPG.


* BUILD INSTRUCTIONS

  GnuPG 2.6 depends on the following GnuPG related packages:

    npth         (https://gnupg.org/ftp/gcrypt/npth/)
    libgpg-error (https://gnupg.org/ftp/gcrypt/libgpg-error/)
    libgcrypt    (https://gnupg.org/ftp/gcrypt/libgcrypt/)
    libksba      (https://gnupg.org/ftp/gcrypt/libksba/)
    libassuan    (https://gnupg.org/ftp/gcrypt/libassuan/)

  You should get the latest versions of course, the GnuPG configure
  script complains if a version is not sufficient.

  Several other standard libraries are also required.  The configure
  script prints diagnostic messages if one of these libraries is not
  available and a feature will not be available.

  You also need the Pinentry package for most functions of GnuPG;
  however it is not a build requirement.  Pinentry is available at
  https://gnupg.org/ftp/gcrypt/pinentry/ .

  After building and installing the above packages in the order as
  given above, you may continue with GnuPG installation (you may also
  just try to build GnuPG to see whether your already installed
  versions are sufficient).

  As with all packages, you just have to do

    mkdir build
    cd build
    ../configure
    make
    make check
    make install

  The "make check" is optional but highly recommended.  To run even
  more tests you may add "--enable-all-tests" to the configure run.
  Before running the "make install" you might need to become root.

  If everything succeeds, you have a working GnuPG with support for
  OpenPGP, S/MIME, ssh-agent, and smartcards.

  In case of problem please ask on the gnupg-users@gnupg.org mailing
  list for advise.

  Instruction on how to build for Windows can be found in the file
  doc/HACKING in the section "How to build an installer for Windows".
  This requires some experience as developer.

  You may run

    gpgconf -L

  to view the directories used by GnuPG.

** Quick build method on Unix

  To quickly build all required software without installing it, the
  Speedo target may be used.  But first you need to make sure that the
  toolchain is installed.  On a Debian based system it should be
  sufficient to run as root:

    apt-get install build-essential libusb-1.0-0-dev libsqlite3-dev \
                    libldap-dev libreadline-dev patchelf

  (libldap-dev and libreadline-dev are not strictly necessary but
   are highly suggested.)

  Then as regular user run

    make -f build-aux/speedo.mk native

  This target downloads all required libraries and does a native build
  of GnuPG to PLAY/inst/.  After the build the entire software
  including all libraries can be installed into an arbitrary location
  using for example:

    make -f build-aux/speedo.mk install SYSROOT=/usr/local/gnupg26

  and run the binaries like

    /usr/local/gnupg26/bin/gpg

  which will also start any daemon from the same directory.  Make sure
  to stop already running daemons or use a different GNUPGHOME.

  If you want to use the gnupg-w32-n.m.n_somedate.tar.xz tarball you
  only need to change the first make invocation to

      make -f build-aux/speedo.mk this-native

  The advantage of this alternative tarball is that all libraries are
  included and thus the Makefile does not need to download new
  tarballs.  Note that in any case all downloaded files come with
  signatures which are verified by the Makefile commands.  The
  patchelf command is required to change the search path for the
  shared libraries in the binaries to relative directories.

** Specific build problems on some machines:

*** Apple OSX 10.x using XCode

  On some versions the correct location of a header file can't be
  detected by configure.  To fix that you should run configure like
  this

    ./configure  gl_cv_absolute_stdint_h=/usr/include/stdint.h

  Add other options as needed.

*** Cygwin

  Although Cygwin (Posix emulation on top of Windows) is not
  officially supported, GnuPG can be build for that platform.  It
  might be required to invoke configure like this:

    ./configure  ac_cv_type_SOCKET=no

*** Systems without a full C99 compiler

  If you run into problems with your compiler complaining about dns.c
  you may use

    ./configure --disable-libdns

  Add other options as needed.



* RECOMMENDATIONS

** Key database daemon

  Since version 2.3.0 it is possible to store the keys in an SQLite
  database instead of the keyring.kbx file.  This is in particular
  useful for large keyrings or if many instances of gpg and gpgsm may
  run concurrently.  This is implemented using another daemon process,
  the "keyboxd".  To enable the use of the keyboxd put the option
  "use-keyboxd" into the configuration file ~/.gnupg/common.conf or the
  global /etc/gnupg/common.conf.  See also doc/examples/common.conf.
  Only public keys and X.509 certificates are managed by the keyboxd;
  private keys are still stored as separate files.

  Since version 2.4.1 the keyboxd will be used by default for a fresh
  install; i.e. if a ~/.gnupg directory did not yet exist.

  Note that there is no automatic migration; if the use-keyboxd option
  is enabled keys are not taken from pubring.kbx.  To migrate existing
  keys to the keyboxd do this:

  1. Disable the keyboxd (remove use-keyboxd from common.conf)
  2. Export all public keys
       gpg --export --export-options backup  > allkeys.gpg
       gpgsm --export --armor                > allcerts.gpg
  3. Enable the keyboxd (add use-keyboxd to common.conf)
  4. Import all public keys
       gpg --import --import-options restore < allkeys.gpg
       gpgsm --import                        < allcerts.crt

  In case the keyboxd is not able to startup due to a stale lockfile
  created by another host, the command

     gpgconf --unlock pubring.db

  can be used to remove the lock file.

** Socket directory

  GnuPG uses Unix domain sockets to connect its components (on Windows
  an emulation of these sockets is used).  Depending on the type of
  the file system, it is sometimes not possible to use the GnuPG home
  directory (i.e. ~/.gnupg) as the location for the sockets.  To solve
  this problem GnuPG prefers the use of a per-user directory below the
  the /run (or /var/run) hierarchy for the sockets.  It is thus
  suggested to create per-user directories on system or session
  startup.  For example, the following snippet can be used in
  /etc/rc.local to create these directories:

      [ ! -d /run/user ] && mkdir /run/user
      awk -F: </etc/passwd '$3 >= 1000 && $3 < 65000 {print $3}' \
        | ( while read uid rest; do
              if [ ! -d "/run/user/$uid" ]; then
                mkdir /run/user/$uid
                chown $uid /run/user/$uid
                chmod 700 /run/user/$uid
              fi
            done )

** Conflicts with systemd socket activation

  Some Linux distribution use the meanwhile deprecated --supervised
  option with gpg-agent, dirmngr, and keyboxd.  The idea is that the
  systemd process launches the daemons as soon as gpg or gpgsm try to
  access them.  However, this creates a race condition with GnuPG's
  own on-demand launching of these daemon.  It also conflicts with the
  remote use gpg-agent because the no-autostart feature on the remote
  site will not work as expected.

  If your systems already comes with a systemd enabled GnuPG, you
  should thus tell it not to start its own GnuPG daemons by running
  the following three commands once:

    systemctl --user mask --now gpg-agent.service \
              gpg-agent.socket gpg-agent-ssh.socket \
              gpg-agent-extra.socket gpg-agent-browser.socket
    systemctl --user mask --now dirmngr.service dirmngr.socket
    systemctl --user mask --now keyboxd.service keyboxd.socket

  This way all GnuPG components can handle the startup of their
  daemons on their own and start the correct version.

  The only problem is that for using GnuPG's ssh-agent protocol
  support, the gpg-agent must have been started before ssh.  This can
  either be done with an ssh wrapper running

    gpg-connect-agent updatestartuptty /bye

  for each new tty or by using that command directly after login when
  the anyway required SSH_AUTH_SOCK envvar is set (see the example in
  the gpg-agent man page).


* DOCUMENTATION

  The complete documentation is in the texinfo manual named
  `gnupg.info'.  Run "info gnupg" to read it.  If you want a
  printable copy of the manual, change to the "doc" directory and
  enter "make pdf" For a HTML version enter "make html" and point your
  browser to gnupg.html/index.html.  Standard man pages for all
  components are provided as well.  An online version of the manual is
  available at [[https://gnupg.org/documentation/manuals/gnupg/]] .  A
  version of the manual pertaining to the current development snapshot
  is at [[https://gnupg.org/documentation/manuals/gnupg-devel/]] .


* Using the legacy version GnuPG 1.4

  The 1.4 version of GnuPG is only intended to allow decryption of old
  data material using legacy keys which are not anymore supported by
  GnuPG 2.x.  To install both versions alongside, it is suggested to
  rename the 1.4 version of "gpg" to "gpg1" as well as the
  corresponding man page.  Newer releases of the 1.4 branch will
  likely do this by default.


* HOW TO GET MORE INFORMATION

  A description of new features and changes since version 2.1 can be
  found in the file "doc/whats-new-in-2.1.txt" and online at
  "https://gnupg.org/faq/whats-new-in-2.1.html" .

  The primary WWW page is "https://gnupg.org"
  The primary FTP site is "https://gnupg.org/ftp/gcrypt/"

  See [[https://gnupg.org/download/mirrors.html]] for a list of
  mirrors and use them if possible.  You may also find GnuPG mirrored
  on some of the regular GNU mirrors.

  We have some mailing lists dedicated to GnuPG:

     gnupg-announce@gnupg.org   For important announcements like new
                                versions and such stuff.  This is a
                                moderated list and has very low traffic.
                                Do not post to this list.

     gnupg-users@gnupg.org      For general user discussion and
                                help.

     gnupg-devel@gnupg.org      GnuPG developers main forum.

  You subscribe to one of the list by sending mail with a subject of
  "subscribe" to x-request@gnupg.org, where x is the name of the
  mailing list (gnupg-announce, gnupg-users, etc.). See
  https://gnupg.org/documentation/mailing-lists.html for archives
  of the mailing lists.

  Please direct bug reports to [[https://bugs.gnupg.org]] or post them
  direct to the mailing list <gnupg-devel@gnupg.org>.

  Please direct questions about GnuPG to the users mailing list or one
  of the PGP newsgroups; please do not direct questions to one of the
  authors directly as we are busy working on improvements and bug
  fixes.  The mailing lists are watched by the authors and we try to
  answer questions as time allows us.

  Commercial grade support for GnuPG is available; for a listing of
  offers see https://gnupg.org/service.html .  Maintaining and
  improving GnuPG requires a lot of time.  Since 2001, g10 Code GmbH,
  a German company owned and headed by GnuPG's principal author Werner
  Koch, is bearing the majority of these costs.



4. Software Versions of the Included Packages
=============================================

GnuPG for Windows depends on several independent developed packages
which are part of the installation.  These packages along with their
version numbers and the SHA-1 checksums of their compressed tarballs
are listed here:

bzip2          1.0.6-g10    6e38be3377340a21a1f13ff84b5e6adce97cd1d4
libassuan      3.0.2        57fb6f59b1a07e5125115454f5ad4cb0665e0eef
libgcrypt      1.11.2       b0d3d966894a5ee3b629e55350464f69e1c7859e
libgpg-error   1.58         a9876a9e4cb54298960bd4202baf891642060428
libksba        1.6.7        781acfb012cbb5328f41efcf82f723524e8d0128
npth           1.8          6f60ce8540453e120d715f269d0c7cfd9e0b0d24
ntbtls         0.3.2        ae52b4d49e17f17951655512949f745385804faf
pinentry       1.3.2        ca7c502f347f248377842f7e68df5e971059e4db
sqlite         3280000      01b9d8fc77085e144dddc87456c9783e53d09a53
zlib           1.2.12       207ba741d387e2c1607104cf0bd8cff27deb2605


5. Legal Notices Pertaining to the Individual Packages
======================================================

GnuPG for Windows consist of several independent developed packages,
available under different license conditions.  Most of these packages
are however available under the GNU General Public License (GNU GPL).
Common to all is that they are free to use without restrictions, may
be modified and that modifications may be distributed.  If the source
file (i.e. gnupg-w32-VERSION_DATE.tar.xz) is distributed along with
the installer and the use of the GNU GPL has been pointed out,
distribution is in all cases possible.

What follows is a list of copyright statements.

Here is a list with collected copyright notices. For details see the
description of each individual package.  [Compiled by wk 2017-11-07]


GNUPG is

  Copyright (C) 1997-2017 Werner Koch
  Copyright (C) 1994-2017 Free Software Foundation, Inc.
  Copyright (C) 2003-2017 g10 Code GmbH
  Copyright (C) 2002 Klarälvdalens Datakonsult AB
  Copyright (C) 1995-1997, 2000-2007 Ulrich Drepper <drepper@gnu.ai.mit.edu>
  Copyright (C) 1994 X Consortium
  Copyright (C) 1998 by The Internet Society.
  Copyright (C) 1998-2004 The OpenLDAP Foundation
  Copyright (C) 1998-2004 Kurt D. Zeilenga.
  Copyright (C) 1998-2004 Net Boolean Incorporated.
  Copyright (C) 2001-2004 IBM Corporation.
  Copyright (C) 1999-2003 Howard Y.H. Chu.
  Copyright (C) 1999-2003 Symas Corporation.
  Copyright (C) 1998-2003 Hallvard B. Furuseth.
  Copyright (C) 1992-1996 Regents of the University of Michigan.
  Copyright (C) 2000 Dimitrios Souflis
  Copyright (C) 2008,2009,2010,2012-2016 William Ahern

  GnuPG is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 3 of the License, or
  (at your option) any later version.

  GnuPG is distributed in the hope that it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
  or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
  License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, see <https://www.gnu.org/licenses/>.


LIBGCRYPT is

  Copyright (C) 1989,1991-2017 Free Software Foundation, Inc.
  Copyright (C) 1994 X Consortium
  Copyright (C) 1996 L. Peter Deutsch
  Copyright (C) 1997 Werner Koch
  Copyright (C) 1998 The Internet Society
  Copyright (C) 1996-1999 Peter Gutmann, Paul Kendall, and Chris Wedgwood
  Copyright (C) 1996-2006 Peter Gutmann, Matt Thomlinson and Blake Coverett
  Copyright (C) 2003 Nikos Mavroyanopoulos
  Copyright (C) 2006-2007 NTT (Nippon Telegraph and Telephone Corporation)
  Copyright (C) 2012-2017 g10 Code GmbH
  Copyright (C) 2012 Simon Josefsson, Niels Möller
  Copyright (c) 2012 Intel Corporation
  Copyright (C) 2013 Christian Grothoff
  Copyright (C) 2013-2017 Jussi Kivilinna
  Copyright (C) 2013-2014 Dmitry Eremin-Solenikov
  Copyright (C) 2014 Stephan Mueller
  Copyright (C) 2017 Bundesamt für Sicherheit in der Informationstechnik

  Libgcrypt is free software; you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as
  published by the Free Software Foundation; either version 2.1 of
  the License, or (at your option) any later version.

  Libgcrypt is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this program; if not, see <http://www.gnu.org/licenses/>.


LIBGPG-ERROR is

  Copyright (C) 2003-2004, 2010, 2013-2017 g10 Code GmbH

  libgpg-error is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public License
  as published by the Free Software Foundation; either version 2.1 of
  the License, or (at your option) any later version.

  libgpg-error is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with this program; if not, see <http://www.gnu.org/licenses/>.


LIBASSUAN is

  Copyright (C) 1992-2013 Free Software Foundation, Inc.
  Copyright (C) 1994 X Consortium
  Copyright (C) 2000 Werner Koch (dd9jn)
  Copyright (C) 2001-2016 g10 Code GmbH
  Copyright (C) 2004 Simon Josefsson

  Assuan is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as
  published by the Free Software Foundation; either version 2.1 of
  the License, or (at your option) any later version.

  Assuan is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this program; if not, see <http://www.gnu.org/licenses/>.


LIBKSBA is

  Copyright (C) 2001, 2002, 2003, 2004, 2005, 2006, 2010, 2011
                2012, 2013, 2014, 2015 g10 Code GmbH
  Copyright (C) 2001, 2002, 2003, 2007 Free Software Foundation, Inc.
  Copyright (C) 2000, 2001 Fabio Fiorina

  The library and the header files are distributed under the following
  terms (LGPLv3+/GPLv2+):

  KSBA is free software; you can redistribute it and/or modify
  it under the terms of either

    - the GNU Lesser General Public License as published by the Free
      Software Foundation; either version 3 of the License, or (at
      your option) any later version.

  or

    - the GNU General Public License as published by the Free
      Software Foundation; either version 2 of the License, or (at
      your option) any later version.

  or both in parallel, as here.

  KSBA is distributed in the hope that it will be useful, but WITHOUT
  ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
  or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public
  License for more details.

  The other parts (e.g. manual, build system, tests) are distributed
  under the following terms (GPLv3):

  KSBA is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 3 of the License, or
  (at your option) any later version.

  KSBA is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.


NPTH is

  Copyright (C) 2011, 2012, 2014, 2015, 2017 g10 Code GmbH

  nPth is free software; you can redistribute it and/or modify
  it under the terms of the GNU Lesser General Public License as
  published by the Free Software Foundation; either version 2.1 of
  the License, or (at your option) any later version.

  nPth is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See
  the GNU Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this program; if not, see <https://www.gnu.org/licenses/>.


NTBTLS is

  Copyright (C) 2006-2014 Brainspark B.V.
  Copyright (C) 2014-2017 g10 Code GmbH

  NTBTLS is free software; you can redistribute it and/or modify
  it under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 3 of the License, or
  (at your option) any later version.

  NTBTLS is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
  GNU General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, see <http://www.gnu.org/licenses/>.


PINENTRY is

  Copyright (C) 1999 Robert Bihlmeyer <robbe@orcus.priv.at>
  Copyright (C) 2001-2004, 2007-2008, 2010, 2015-2016 g10 Code GmbH
  Copyright (C) 2002, 2008 Klarälvdalens Datakonsult AB (KDAB)
  Copyright (C) 2004 by Albrecht Dreß <albrecht.dress@arcor.de>
  Copyright 2007 Ingo Klöcker
  Copyright (C) 2014 Serge Voilokov
  Copyright (C) 2015 Daiki Ueno
  Copyright (C) 2015 Daniel Kahn Gillmor <dkg@fifthhorseman.net>
  Copyright 2016 Intevation GmbH

  PINENTRY is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  PINENTRY is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with this program; if not, see <https://www.gnu.org/licenses/>.


GPGME is

  Copyright (C) 1991-2013 Free Software Foundation, Inc.
  Copyright (C) 2000-2001 Werner Koch
  Copyright (C) 2001-2017 g10 Code GmbH
  Copyright (C) 2002 Klarälvdalens Datakonsult AB
  Copyright (C) 2004-2008 Igor Belyi
  Copyright (C) 2002 John Goerzen
  Copyright (C) 2014, 2015 Martin Albrecht
  Copyright (C) 2015 Ben McGinnes
  Copyright (C) 2015-2016 Bundesamt für Sicherheit in der Informationstechnik
  Copyright (C) 2016 Intevation GmbH

  GPGME is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as
  published by the Free Software Foundation; either version 2.1 of
  the License, or (at your option) any later version.

  GPGME is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with this program; if not, see <http://www.gnu.org/licenses/>.


NSIS is

  Copyright 1999-2009 Nullsoft and Contributors
  Copyright 2002-2008 Amir Szekely
  Copyright 2003 Ramon

  This license applies to everything in the NSIS package, except where
  otherwise noted.

  This software is provided 'as-is', without any express or implied
  warranty. In no event will the authors be held liable for any
  damages arising from the use of this software.

  Permission is granted to anyone to use this software for any
  purpose, including commercial applications, and to alter it and
  redistribute it freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must
     not claim that you wrote the original software. If you use this
     software in a product, an acknowledgment in the product
     documentation would be appreciated but is not required.

  2. Altered source versions must be plainly marked as such, and must
     not be misrepresented as being the original software.

  3. This notice may not be removed or altered from any source
     distribution.

  The user interface used with the installer is

  Copyright 2002-2009 Joost Verburg

  [It is distributed along with NSIS and the same conditions as stated
   above apply]


TinySCHEME is part of the GnuPG package and is

  Copyright (c) 2000, Dimitrios Souflis
  All rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
  met:

  Redistributions of source code must retain the above copyright notice,
  this list of conditions and the following disclaimer.

  Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

  Neither the name of Dimitrios Souflis nor the names of the
  contributors may be used to endorse or promote products derived from
  this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
  ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
  LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
  A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE REGENTS OR
  CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
  EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
  PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
  LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


LIBDNS is part of the GnuPG package and is

  Copyright (c) 2008, 2009, 2010, 2012-2016  William Ahern

  Permission is hereby granted, free of charge, to any person obtaining a
  copy of this software and associated documentation files (the
  "Software"), to deal in the Software without restriction, including
  without limitation the rights to use, copy, modify, merge, publish,
  distribute, sublicense, and/or sell copies of the Software, and to permit
  persons to whom the Software is furnished to do so, subject to the
  following conditions:

  The above copyright notice and this permission notice shall be included
  in all copies or substantial portions of the Software.

  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
  OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
  MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN
  NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM,
  DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
  OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
  USE OR OTHER DEALINGS IN THE SOFTWARE.


ZLIB is

  (C) 1995-2013 Jean-loup Gailly and Mark Adler

  This software is provided 'as-is', without any express or implied
  warranty.  In no event will the authors be held liable for any damages
  arising from the use of this software.

  Permission is granted to anyone to use this software for any purpose,
  including commercial applications, and to alter it and redistribute it
  freely, subject to the following restrictions:

  1. The origin of this software must not be misrepresented; you must not
     claim that you wrote the original software. If you use this software
     in a product, an acknowledgment in the product documentation would be
     appreciated but is not required.
  2. Altered source versions must be plainly marked as such, and must not be
     misrepresented as being the original software.
  3. This notice may not be removed or altered from any source distribution.

  Jean-loup Gailly        Mark Adler
  jloup@gzip.org          madler@alumni.caltech.edu


BZIP2 is

  This program, "bzip2", the associated library "libbzip2", and all
  documentation, are copyright (C) 1996-2010 Julian R Seward.  All
  rights reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions
  are met:

  1. Redistributions of source code must retain the above copyright
     notice, this list of conditions and the following disclaimer.

  2. The origin of this software must not be misrepresented; you must
     not claim that you wrote the original software.  If you use this
     software in a product, an acknowledgment in the product
     documentation would be appreciated but is not required.

  3. Altered source versions must be plainly marked as such, and must
     not be misrepresented as being the original software.

  4. The name of the author may not be used to endorse or promote
     products derived from this software without specific prior written
     permission.

  THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
  OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
  DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
  GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
  INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
  NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
  SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.


SQLITE has

  been put into the public-domain by its author D. Richard Hipp:
  The author disclaims copyright to this source code.  In place of
  a legal notice, here is a blessing:

      May you do good and not evil.
      May you find forgiveness for yourself and forgive others.
      May you share freely, never taking more than you give.


***end of file ***
