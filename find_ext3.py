#!/usr/bin/env python
"""
Find ext3 file-system within a disk image.
"""
__docformat__ = "reStructuredText en_gb"

import os
import sys
import re
import mmap
import optparse
import struct
import itertools
import collections
import pprint
import subprocess


# =============================================================================
class Ext2Header( object ):
    lStructFormat = [
        "I", "s_inodes_count",
        "I", "s_blocks_count",
        "I", "s_r_blocks_count",
        "I", "s_free_blocks_count",
        "I", "s_free_inodes_count",
        "I", "s_first_data_block",
        "I", "s_log_block_size",
        "I", "s_log_frag_size",
        "I", "s_blocks_per_group",
        "I", "s_frags_per_group",
        "I", "s_inodes_per_group",
        "I", "s_mtime",
        "I", "s_wtime",

        "H", "s_mnt_count",
        "H", "s_max_mnt_count",
        "H", "s_magic (0xEF53)",
        "H", "s_state (1=VALID_FS, 0=ERROR_FS)",
        "H", "s_errors (1=ERRORS_CONTINUE, 2=ERRORS_RO, 3=ERRORS_PANIC)",
        "H", "s_minor_rev_level",

        "I", "s_lastcheck",
        "I", "s_checkinterval",
        "I", "s_creator_os (0=OS_LINUX, 1=OS_HURD, 2=OS_MASIX, 3=OS_FREEBSD, 4=OS=LITES)",
        "I", "s_rev_level (0=GOOD_OLD_REV, 1=DYNAMIC_REV)",

        "H", "s_def_resuid",
        "H", "s_def_resgid",

        "I", "s_first_ino",

        "H", "s_inode_size (must be <= 1<<s_log_frag_size)",
        "H", "s_block_group_nr",

        "I", """s_feature_compat (Mask of the following flags:
                   FEATURE_COMPAT_DIR_PREALLOC:  0x0001
                   FEATURE_COMPAT_IMAGIC_INODES: 0x0002
                   FEATURE_COMPAT_HAS_JOURNAL:   0x0004
                   FEATURE_COMPAT_EXT_ATTR:      0x0008
                   FEATURE_COMPAT_RESIZE_INO:    0x0010
                   FEATURE_COMPAT_DIR_INDEX:     0x0020
                   )
                   """,
        "I", """s_feature_incompat (Mask of the following flags:
                   # FEATURE_INCOMPAT_COMPRESSION: 0x0001
                   # FEATURE_INCOMPAT_FILETYPE:    0x0002
                   # FEATURE_INCOMPAT_RECOVER:     0x0004
                   # FEATURE_INCOMPAT_JOURNAL_DEV: 0x0008
                   # FEATURE_INCOMPAT_META_BG:     0x0010
                   # )
                   """,
        "I", """s_feature_ro_compat (Mask of the following flags:
                   # FEATURE_RO_COMPAT_SPARSE_SUPER:   0x0001
                   # FEATURE_RO_COMPAT_LARGE_FILE:     0x0002
                   # FEATURE_RO_COMPAT_BTREE_DIR:      0x0004
                   # )
                   """,
        "16s", "s_uuid (128-bit, so we'll treat it as an 8-char string)",
        "16s", "s_volume_name",
        "64s", "s_last_mounted",

        "I", "s_algo_bitmap (0=LZV1_ALG, 1=LZRW3A_ALG, 2=GZIP_ALG, 3=BZIP2_ALG, 4=LZO_ALG)",

        "B", "s_prealloc_blocks",
        "B", "s_prealloc_dir_blocks",

        "16s", "s_journal_uuid",

        "I", "s_journal_inum",
        "I", "s_journal_dev",
        "I", "s_last_orphan",

        "16s", "s_hash_seed (Actually 4I, but we want to keep it as a single member)",

        "Bxxx", "s_def_hash_version",

        "I", "s_default_mount_options",
        "I", "s_first_meta_bg",
        "760s", "Unused",
        ]

    rStructFormat = "<" + "".join(
            # Select elements with an odd index
            itertools.compress(
                lStructFormat,
                itertools.cycle([1,0])
                )
            )

    sStructExt2 = struct.Struct(rStructFormat)

    clsNamedTupleExt2 = collections.namedtuple(
            "Ext2", 
            " ".join(
                    # NB: This is a list comprehension
                    x.lstrip().partition(" ")[0] for x in 
                    itertools.compress(
                        lStructFormat,
                        itertools.cycle([0,1])
                        )
                )
            )

    # -------------------------------------------------------------------------
    def __init__(self, sMap, iOffset):
        self.iOffset = iOffset
        self.t = self.clsNamedTupleExt2(
                *self.sStructExt2.unpack_from(sMap, iOffset)
                )

    # -------------------------------------------------------------------------
    def __str__(self):
        return "%d %s (%s kB)" % (
                self.iOffset,
                self.t.s_volume_name, 
                1024 << self.t.s_log_block_size
                )

    # -------------------------------------------------------------------------
    def __call__(self, rImageFile):
        lCommand = [
                "dumpe2fs",
                "-o", "blocksize=%d" % (1024 << self.t.s_log_block_size),
                "-o", "superblock=%d" % (self.iOffset / (1024 << self.t.s_log_block_size)),
                rImageFile,
                ]

        with file(os.devnull, "w+r") as sDevNull:
            return subprocess.call(
                    lCommand,
                    stdin=sDevNull,
                    stdout=sDevNull,
                    stderr=sDevNull,
                    shell=False,
                    )

# =============================================================================
if __name__ == "__main__":
    sOptionParser = optparse.OptionParser(usage="%prog [options] disk_image")
    sOptionParser.description = __doc__
    lOpts, lArgs = sOptionParser.parse_args()

    rImageFile = lArgs[0]

    # Note: Cannot use os.stat() et al on loopback devices, but this method 
    # seems to work.
    sFH = file(rImageFile, "rb")
    sFH.seek(0, 2)
    iSize = sFH.tell()
    iFH = sFH.fileno()

    sMap = mmap.mmap(iFH, iSize, mmap.MAP_PRIVATE, mmap.PROT_READ)

    # Cf. http://www.nongnu.org/ext2-doc/ext2.html#SUPERBLOCK
    # Magic bytes are (0x53, 0xef), and sit at offset 56 (bytes)
    # Volume name ("label") is 16 bytes at offset 120 (bytes)
    for sMatch in re.finditer(chr(0x53)+chr(0xef)+".{62}[a-zA-Z0-1]{0,15}"+chr(0), sMap):
        iHeaderOffset = sMatch.start() - 56
        if iHeaderOffset < 0:
            # Means that the `re` module has truncated the offset value. Abort.
            break
        sHeader = Ext2Header(sMap, iHeaderOffset)
        if sHeader(rImageFile) == 0:
            print
            print "OK\t%s" % sHeader
            print
        else:
            print "FAIL\t%s" % sHeader
        sys.stdout.flush()
