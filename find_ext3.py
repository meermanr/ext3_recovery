#!/usr/bin/env python
"""
Find ext3 file-system within a disk image, and optionally perform a (shallow) 
test of the file-systems' validity.

Note that the --check option requires that you can create/detach loopback 
devices with 'losetup'
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
import time


# =============================================================================
class Ext4Header( object ):
    # Cf.  
    # https://ext4.wiki.kernel.org/articles/e/x/t/Ext4_Disk_Layout_aecb.html
    lStructFormat = [
        "I", "s_inodes_count",
        "I", "s_blocks_count",
        "I", "s_r_blocks_count",
        "I", "s_free_blocks_count",
        "I", "s_free_inodes_count",
        "I", "s_first_data_block",
        "I", "s_log_block_size",
        "I", "s_log_frag_size",     # Obsolete in ext4
        "I", "s_blocks_per_group",
        "I", "s_frags_per_group",   # Obsolete in ext4
        "I", "s_inodes_per_group",
        "I", "s_mtime",
        "I", "s_wtime",

        "H", "s_mnt_count",
        "H", "s_max_mnt_count",
        "H", "s_magic (0xEF53)",
        "H", "s_state (1=VALID_FS, 2=ERROR_FS, 4=Orphans being recovered)",
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
                   FEATURE_COMPAT_DIR_PREALLOC:     0x0001
                   FEATURE_COMPAT_IMAGIC_INODES:    0x0002
                   FEATURE_COMPAT_HAS_JOURNAL:      0x0004
                   FEATURE_COMPAT_EXT_ATTR:         0x0008
                   FEATURE_COMPAT_RESIZE_INO:       0x0010
                   FEATURE_COMPAT_DIR_INDEX:        0x0020
                   Lazy BG                          0x0040
                   Exclude inode                    0x0080
                   )
                   """,
        "I", """s_feature_incompat (Mask of the following flags:
                   FEATURE_INCOMPAT_COMPRESSION:    0x0001
                   FEATURE_INCOMPAT_FILETYPE:       0x0002
                   FEATURE_INCOMPAT_RECOVER:        0x0004
                   FEATURE_INCOMPAT_JOURNAL_DEV:    0x0008
                   FEATURE_INCOMPAT_META_BG:        0x0010
                   Extents                          0x0040
                   FS size of 2**64 blocks          0x0080
                   Multiple mount protection        0x0100
                   Flexible block groups            0x0200
                   Data in dir entry                0x1000
                   )
                   """,
        "I", """s_feature_ro_compat (Mask of the following flags:
                   FEATURE_RO_COMPAT_SPARSE_SUPER:  0x0001
                   FEATURE_RO_COMPAT_LARGE_FILE:    0x0002
                   FEATURE_RO_COMPAT_BTREE_DIR:     0x0004
                   Sizes in logical blocks          0x0008
                   Group desc. checksums            0x0010
                   Ext3 32k limit relaxed           0x0020
                   Large inodes                     0x0040
                   Snapshot                         0x0080
                   )
                   """,
        "16s", "s_uuid (128-bit, so we'll treat it as an 8-char string)",
        "16s", "s_volume_name",
        "64s", "s_last_mounted",

        "I", "s_algo_bitmap (0=LZV1_ALG, 1=LZRW3A_ALG, 2=GZIP_ALG, 3=BZIP2_ALG, 4=LZO_ALG)",

        "B", "s_prealloc_blocks",
        "B", "s_prealloc_dir_blocks",
        "H", "s_reserved_gdt_blocks",

        "16s", "s_journal_uuid",

        "I", "s_journal_inum",
        "I", "s_journal_dev",
        "I", "s_last_orphan",

        "16s", "s_hash_seed (Actually 4I, but we want to keep it as a single member)",

        "B", "s_def_hash_version",
        "B", "s_jnl_backup_type",
        "H", "s_desc_size",

        "I", "s_default_mount_options",
        "I", "s_first_meta_bg",
        "I", "s_mkfs_time",

        "68s", "s_jnl_blocks",  # Actually 17I, but we want to keep it as a single member

        "I", "s_blocks_count_hi",
        "I", "s_r_blocks_count_hi",
        "I", "s_free_blocks_count_hi",

        "H", "s_min_extra_isize",
        "H", "s_want_extra_isize",

        "I", "s_flags",

        "H", "s_raid_stride",
        "H", "s_mmp_interval",

        "Q", "s_mmp_block",

        "I", "s_raid_stripe_width",

        "B", "s_log_groups_per_flex",
        "B", "s_reserved_char_pad",

        "H", "s_reserved_pad",

        "Q", "s_kbytes_written",

        "I", "s_snapshot_inum",
        "I", "s_snapshot_id",

        "Q", "s_snapshot_r_blocks_count",

        "I", "s_snapshot_list",
        "I", "s_error_count",
        "I", "s_first_error_time",
        "I", "s_first_error_ino",

        "Q", "s_first_error_block",

        "32s", "s_first_error_func",    # Actually 32B, but we want it as a single member

        "I", "s_first_error_line",
        "I", "s_last_error_time",
        "I", "s_last_error_ino",
        "I", "s_last_error_line",

        "Q", "s_last_error_block",

        "32s", "s_last_error_func", # Actually 32B, but we want it as a single member
        "64s", "s_mount_opts",      # Actually 64B (ASCIIZ string)

        "I", "s_usr_quota_inum",
        "I", "s_grp_quota_inum",
        "I", "s_overhead_blocks",
        "I", "s_checksum",          # CRC32 checksum of superblock (PROPOSED)

        "432s", "Unused",
        ]

    rStructFormat = "<" + "".join(
            # Select elements with an odd index
            itertools.compress(
                lStructFormat,
                itertools.cycle([1,0])
                )
            )

    sStructExt2 = struct.Struct(rStructFormat)
    assert sStructExt2.size == 1024, \
            "Format string describes a structure with the wrong size"

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

        # Sanity checks (raise ValueError)
        if self.t.s_log_block_size > 16:
            raise ValueError("s_log_block_size too big: %d" \
                    % self.t.s_log_block_size)

        if self.t.s_log_groups_per_flex > 16:
            raise ValueError("s_log_groups_per_flex too big: %d" \
                    % self.t.s_log_groups_per_flex)

        if self.t.s_log_frag_size > 16:
            raise ValueError("s_log_frag_size too big: %d" \
                    % self.t.s_log_frag_size)

        if not self.t.s_volume_name.partition("\x00")[0].isalnum():
            raise ValueError("s_volume_name is not ASCII: %s" \
                    % self.t.s_volume_name)

    # -------------------------------------------------------------------------
    def get_origin(self):
        if self.t.s_block_group_nr == 0:
            return self.iOffset - 1024   # First superblock is always at 1024
        else:
            return self.iOffset - (
                    self.t.s_blocks_per_group
                    * self.t.s_block_group_nr
                    * (1024 << self.t.s_log_block_size)
                    )

    # -------------------------------------------------------------------------
    def __str__(self):
        return "%d %s #%d %s kB %d bpg, origin %d" % (
                self.iOffset,
                self.t.s_volume_name, 
                self.t.s_block_group_nr,
                1024 << self.t.s_log_block_size,
                self.t.s_blocks_per_group,
                self.get_origin(),
                )

    # -------------------------------------------------------------------------
    def __call__(self, rImageFile, yStopOnValid=False):
        """
        Perform a (shallow) check of this superblock within its containing 
        file, `rImageFile`.

        :Parameters:
            rImageFile : str
                File-system path to a file-like object that holds this 
                superblock at offset `self.iOffset`.
            yStopOnValid : bool
                If this is set and the check suggests the superblock is valid 
                exit the script immediately.

        :Returns:
            0: Superblock does not seem valid
            1: Superblock seems valid
            None: Check could not be performed (`losetup` permission problems?)
        """
        if self.get_origin() < 0:
            return None

        with file(os.devnull, "w+r") as sDevNull:
            lCommand = [
                    "losetup",
                    "--find",
                    "--read-only",
                    "--verbose",
                    rImageFile,
                    "--offset", str(self.get_origin()),
                    ]

            rOutput = ""
            iRetries = 10
            while iRetries > 0:
                iRetries -= 1
                try:
                    rOutput = subprocess.check_output(
                            lCommand,
                            stdin=sDevNull,
                            shell=False,
                            )
                except:
                    time.sleep(0.1)
                    continue
                else:
                    break

            if ("Loop device is ") not in rOutput:
                return None

            rDevice = rOutput.partition("Loop device is ")[2].strip()

            iReturnCode = 1
            try:
                lCommand = [
                        "dumpe2fs",
                        "-o", "blocksize=%d" % (
                            1024 << self.t.s_log_block_size),
                        "-o", "superblock=%d" % (
                            self.t.s_block_group_nr
                            * self.t.s_blocks_per_group
                            ),
                        rDevice,
                        ]

                iReturnCode = subprocess.call(
                        lCommand,
                        stdin=sDevNull,
                        stdout=sDevNull,
                        stderr=sDevNull,
                        shell=False,
                        )

                return {0: 1}.get(iReturnCode, 0)

            finally:
                if yStopOnValid and iReturnCode == 0:
                    print "Exiting due to --stop-on-valid. " \
                          " File-system is at %s" % rDevice

                    print "Recommended next step: " \
                          "fsck.ext4 -C 0 -n -f -B %d -b %d %s" % (
                            1024 << self.t.s_log_block_size,
                            self.t.s_block_group_nr
                            * self.t.s_blocks_per_group,
                            rDevice,
                            )
                    exit()

                lCommand = [
                        "losetup",
                        "--detach",
                        rDevice,
                        ]

                while True:
                    try:
                        subprocess.check_call(
                                lCommand,
                                stdin=sDevNull,
                                stdout=sDevNull,
                                stderr=sDevNull,
                                shell=False,
                                )
                    except:
                        time.sleep(0.01)
                        continue
                    else:
                        break


# -----------------------------------------------------------------------------
def gen_chunks(iStart, iFinish, iCount=10000, iMinChunkSize=0):
    """
    Return a generator that yields `iCount` offsets that overlap by at least 
    1024 bytes (the size of an Ext4 header).

    :Parameters:
        iStart : int
            Beginning of range to yield
        iFinish : int
            End of range to yield
        iCount : int
            Maximum number of chunks to yield. May yield fewer due to need to 
            overlap by 1024 bytes.
        iMinChunkSize : int
            Minimum range to cover with a pair of offsets. Any value provided 
            will be subject to clamping in order to guarantee that progress can 
            be made.

    :RType: Generator
    :Returns:
        Iterable that yields 2-tuples of integers (iStart, iEnd)
    """
    iOverlap = 1024
    iRange = iFinish - iStart

    iChunkSize = (iRange + iOverlap) // iCount

    # Worst-case: Cover every offset twice
    iMinChunkSize = max(iMinChunkSize, 2 * iOverlap)
    iChunkSize = max(iChunkSize, iMinChunkSize)

    iEnd = iStart + iChunkSize

    yield iStart, min(iEnd, iFinish)
    while iEnd < iFinish:
        iStart += iChunkSize - iOverlap
        iEnd += iChunkSize - iOverlap
        yield iStart, min(iEnd, iFinish)

# =============================================================================
if __name__ == "__main__":
    sOptionParser = optparse.OptionParser(usage="%prog [options] disk_image")
    sOptionParser.description = __doc__

    sOptionParser.add_option(
            "--check",
            help="Validate superblock with dumpe2fs",
            action="store_true",
            default=False,
            dest="yCheck",
            )

    sOptionParser.add_option(
            "--stop-on-valid",
            help="(Implies --check) Exit immediately if check succeeds.",
            action="store_true",
            default=False,
            dest="yStop",
            )

    sOptionParser.add_option(
            "--start",
            help="Starting offset, defaults to 0",
            action="store",
            type="int",
            default=0,
            dest="iStart",
            )

    sOptionParser.add_option(
            "--finish",
            help="Final offset, defaults to end of file",
            action="store",
            type="int",
            default=None,
            dest="iFinish",
            )


    sOpts, lArgs = sOptionParser.parse_args()

    if sOpts.yStop:
        sOpts.yCheck = True

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
    # Volume name ("label") is 16 bytes (NULL terminated) at offset 120 (bytes)

    sPattern = re.compile(chr(0x53)+chr(0xef)+".{62}[a-zA-Z0-1]{0,15}"+chr(0))

    iStart = sOpts.iStart
    iFinish = sOpts.iFinish or iSize
    iFinish = max(iFinish, iStart+1024)
    iFinish = min(iFinish, iSize)

    for iStartPos, iEndPos in gen_chunks(
            iStart,
            iFinish,
            iCount=float("+inf"),           # As many as possible
            iMinChunkSize=512*1024*1024,
            ):
        try:
            iPos = iStartPos
            # Note: iPos==-1 when there is no match in this chunk
            while iStartPos <= iPos <= iEndPos:
                try:
                    iPos = sMap.find("\x53\xEF", iPos, iEndPos)

                    if iPos == -1:
                        # No match in this chunk
                        break

                    iHeaderOffset = iPos - 56
                    sHeader = Ext4Header(sMap, iHeaderOffset)

                    # Display findings

                    if sOpts.yCheck:
                        iStatus = sHeader(rImageFile, yStopOnValid=sOpts.yStop)
                        if iStatus is None:
                            print "ERROR\t%s %s" % (rImageFile, sHeader)
                        elif iStatus == 1:
                            print "OK\t%s %s" % (rImageFile, sHeader)
                        elif iStatus == 0:
                            print "BAD\t%s %s" % (rImageFile, sHeader)
                        else:
                            assert False, \
                                    "Unhandled status code from sHeader.__call__"
                    else:
                        print "%s %s" % (rImageFile, sHeader)

                    sys.stdout.flush()

                except ValueError as sEx:
                    continue

                finally:
                    iPos += 1

            # Display progress update

            print >> sys.stderr, "Progress: %.2f%%\t(%d of %d)" % (
                    100 * (float(iEndPos) / iFinish),
                    iEndPos,
                    iFinish,
                    )

            sys.stderr.flush()

        except:
            print "Aborting at offset %d" % iStartPos
            sys.stdout.flush()
            raise
