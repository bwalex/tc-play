#!/bin/sh

#############################################################
# This script takes a volume file and reduces its effective
# compressed size by creating a new zero-filled volume
# and only copying over the header, hidden header and the
# respective backup headers into the new volume.
#
# Since the new file consists mostly of zeros, it compresses
# rather well.
#############################################################

if [ $# -lt 2 ]; then
  echo "Usage: $0 <src volume> <dst volume>"
  exit 1
fi

SRC_VOL=$1
DST_VOL=$2

# Find the total size of the source volume, in bytes.
SZ=`stat -c "%s" "$SRC_VOL"`

# Find the total size of the source volume, in blocks.
SZ_BLOCKS=`echo "$SZ / 512" | bc`

# Find the block at which the backup header area starts.
BCK_HDR_START=`echo "$SZ_BLOCKS - 256" | bc`

# Define the sizes of the header and backup header areas,
# in blocks.
HDR_AREA_BLOCKS=256
BCK_HDR_AREA_BLOCKS=256

# Create new zero-filled volume with the same size as the
# source volume.
dd if=/dev/zero of="$DST_VOL" bs=512 count="$SZ_BLOCKS"

# Copy over the header area.
dd if="$SRC_VOL" of="$DST_VOL" bs=512 count="$HDR_AREA_BLOCKS"     \
    conv=notrunc

# Copy over the backup header area.
dd if="$SRC_VOL" of="$DST_VOL" bs=512 count="$BCK_HDR_AREA_BLOCKS" \
    conv=notrunc seek="$BCK_HDR_START" skip="$BCK_HDR_START"
