#! /bin/sh

#sudo umount /media/VBOXADDITIONS_4.1.12_77218
#sudo mount -t vboxsf Downloads /mnt/HostRW
sudo mount /dev/sdb1 /mnt/RJFDasos
sudo mount -t vboxsf -o uid=1000,gid=1000 ASoS_VM_Shared /mnt/ASoS_VM_Shared
sudo mount -t vboxsf -o uid=1000,gid=1000 Downloads /mnt/HostRW

