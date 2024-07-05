#!/usr/bin/env python3

import tarfile

from io import BytesIO

# create a tar file with some normal files
with tarfile.open(name="payload-common.tar", mode="w") as t:
    f = tarfile.TarInfo(name="file")
    t.addfile(f)

    c = BytesIO(b"contents")
    f = tarfile.TarInfo(name="file-contents")
    f.size = len(c.getbuffer())
    t.addfile(f, c)

    f = tarfile.TarInfo(name="file-user")
    f.uid = 1000
    f.gid = 1000
    t.addfile(f)

    f = tarfile.TarInfo(name="file-mtime")
    f.mtime = 1694006436.1317987
    t.addfile(f)

    f = tarfile.TarInfo(name="executable")
    f.mode = 0o755
    t.addfile(f)

    f = tarfile.TarInfo(name="dir")
    f.type = tarfile.DIRTYPE
    f.mode = 0o750
    t.addfile(f)

    f = tarfile.TarInfo(name="dir/file")
    t.addfile(f)

    f = tarfile.TarInfo(name="symlink")
    f.type = tarfile.SYMTYPE
    f.linkname = "./dir/file"
    t.addfile(f)

    f = tarfile.TarInfo(name="broken-symlink")
    f.type = tarfile.SYMTYPE
    f.linkname = "/nonexistent/symlink/target"
    t.addfile(f)

    f = tarfile.TarInfo(name="hardlink")
    f.type = tarfile.LNKTYPE
    f.linkname = "file"
    t.addfile(f)

    f = tarfile.TarInfo(name="devchr")
    f.type = tarfile.CHRTYPE
    # /dev/null
    f.devmajor = 1
    f.devminor = 3
    t.addfile(f)

    f = tarfile.TarInfo(name="devblk")
    f.type = tarfile.BLKTYPE
    # /dev/dm-0
    f.devmajor = 253
    f.devminor = 0
    t.addfile(f)

    f = tarfile.TarInfo(name="fifo")
    f.type = tarfile.FIFOTYPE
    t.addfile(f)

# create a tar file with some special cases
with tarfile.open(name="payload-special.tar", mode="w") as t:
    f = tarfile.TarInfo(name="file")
    t.addfile(f)

    f = tarfile.TarInfo(name="acl")
    f.pax_headers["SCHILY.acl.access"] = "user::rw-\nuser:root:r--\ngroup::r--\nmask::r--\nother::r--\n"
    t.addfile(f)

    f = tarfile.TarInfo(name="xattr")
    f.pax_headers["SCHILY.xattr.user.foo"] = "bar"
    t.addfile(f)

    f = tarfile.TarInfo(name="selinux")
    f.pax_headers["RHT.security.selinux"] = "system_u:object_r:dummy_t"
    t.addfile(f)

# Generate two tars which use the same contents multiple times in different
# combinations, which is useful for artifact testing.
CONTENTS_A = b"contents-a\n" * 10000
CONTENTS_B = b"contents-b\n" * 10000
CONTENTS_C = b"contents-c\n" * 10000
CONTENTS_D = b"contents-d\n" * 10000


def add_file(tar, name, contents, uid=0):
    c = BytesIO(contents)
    f = tarfile.TarInfo(name=name)
    f.size = len(c.getbuffer())
    f.uid = uid
    tar.addfile(f, c)


with tarfile.open(name="payload-medium-data-size-a.tar.gz", mode="w:gz") as t:
    add_file(t, "file-a-1", CONTENTS_A)
    add_file(t, "file-a-2", CONTENTS_A, uid=1000)
    add_file(t, "file-b-1", CONTENTS_B)
    add_file(t, "file-b-2", CONTENTS_B)
    add_file(t, "file-c-1", CONTENTS_C)

    f = tarfile.TarInfo(name="file-a-1.symlink")
    f.type = tarfile.SYMTYPE
    f.linkname = "./file-a-1"
    t.addfile(f)

    f = tarfile.TarInfo(name="file-a-1.hardlink")
    f.type = tarfile.LNKTYPE
    f.linkname = "file-a-1"
    t.addfile(f)


with tarfile.open(name="payload-medium-data-size-b.tar.gz", mode="w:gz") as t:
    add_file(t, "file-b-1", CONTENTS_B)
    add_file(t, "file-c-1", CONTENTS_C)
    add_file(t, "file-c-2", CONTENTS_C, uid=1000)
    add_file(t, "file-d-1", CONTENTS_D)

    f = tarfile.TarInfo(name="file-b-1.symlink")
    f.type = tarfile.SYMTYPE
    f.linkname = "./file-b-1"
    t.addfile(f)

    f = tarfile.TarInfo(name="file-b-1.hardlink")
    f.type = tarfile.LNKTYPE
    f.linkname = "file-b-1"
    t.addfile(f)
