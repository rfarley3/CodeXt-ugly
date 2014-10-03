#! /bin/sh

# see if usb attached: lsusb | grep Seagate

# if you get errors and -v reveals it's a Lchown, then run sudo perl -MCPAN -e "install qw(Lchown)"

# get the back up drive mounted
# dmesg | tail -30 | grep "Attached SCSI disk"
echo "Mounting backup disk"
sudo mount /mnt/local.backup

# make a snapshot
echo "Taking snapshot to backup disk"
time sudo rsnapshot -c rsnapshot-s2e-commit.conf daily
# excludes s2e-out*, core
# if the oldest is > 6 days old
# ls -al /mnt/local.backup | grep daily
# then do weekly
# keep 4 weeklies and then do a monthly
# only stores 3 monthlies

# tidy up
echo "Unmounting backup disk"
sudo umount /mnt/local.backup
echo "Syncing disk"
sudo sync

echo "Safe to remove back up disk"

