About
==========
tcplay is a free (BSD-licensed), pretty much fully featured (including multiple
keyfiles, cipher cascades, etc) and stable TrueCrypt implementation.

This implementation supports mapping (opening) both system and normal TrueCrypt
volumes, as well as opening hidden volumes and opening an outer volume while
protecting a hidden volume. There is also support to create volumes, including
hidden volumes, etc.

Since tcplay uses dm-crypt (or dm_target_crypt on DragonFly) it makes full use
of any available hardware encryption/decryption support once the volume has been
mapped.

It is based solely on the documentation available on the TrueCrypt website,
many hours of trial and error and the output of the Linux' TrueCrypt client.
As it turns out, most technical documents on TrueCrypt contains mistakes, hence
the trial and error approach.



Implementation notes
==========
DragonFly BSD uses the hybrid OpenSSL + cryptodev(9) approach that can be 
found in crypto-dev.c. OpenSSL is only used for the hash/pbkdf2. The
encryption/decryption is performed via cryptodev(9) with enabled cryptosoft.

On Linux gcrypt is used for the encryption and decryption. For the hash/pbkdf2
either gcrypt or OpenSSL can be used. gcrypt only supports pbkdf2 since its
July 2011 release (1.5.0), while OpenSSL has had pbkdf2 since around December
2010, so its easier to find in most distros.

The crypto options can be chosen with make/Makefile parameters. Building on Linux
is as easy as doing

    make SYSTEM=linux

you can even skip the SYSTEM=linux, since that's the default. To choose the
PBKDF backend, you can use either,

    make PBKDF_BACKEND=openssl

or

    make PBKDF_BACKEND=gcrypt

The interface to device mapper is libdevmapper on Linux and libdm on DragonFly.
libdm is a BSD-licensed version of libdevmapper that I hacked together in a few
hours.

Installation Notes
==================
Ubuntu 12.04
------------
Install dependencies before the `make` step:

`sudo apt-get install uuid-dev libdevmapper-dev libgnutls-dev`

OS Support
==========
tcplay is now available for both DragonFly BSD and Linux. It is a core part of
the DragonFly BSD operating system and is available in a number of linux
distros.



Licensing
==========
The project is under a two-clause BSD license. I would consider dual-licensing
it if required. Drop me an email to discuss the options.



Development
==========
tcplay is pretty much stable, but if you find a bug, please report it.
If anyone wants to add new features or port it to another OS, I'll gladly merge
your changes into this repository so that there is a single point of contact.

I've noticed that sometimes bugs are only reported downstream (e.g. in the
distro's bugtracker). Please make sure those bugs are also reported upstream on
github, otherwise odds are they will never reach me.

Coming features:
 - restoring header from backup header



Bugs in the TrueCrypt documentation
==========
The TrueCrypt documentation is pretty bad and does not really represent the
actual on-disk format nor the encryption/decryption process.

Some notable differences between actual implementation and documentation:
 - PBKDF using RIPEMD160 only uses 2000 iterations if the volume isn't a system
   volume.
 - The keyfile pool is not XOR'ed with the passphrase but modulo-8 summed.
 - Every field *except* the minimum version field of the volume header are in
   big endian.
 - Some volume header fields (creation time of volume and header) are missing
   in the documentation.
 - All two-way cipher cascades are the wrong way round in the documentation,
   but all three-way cipher cascades are correct.

