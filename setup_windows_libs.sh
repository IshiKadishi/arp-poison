#!/bin/bash
set -e

echo "[*] Setting up Windows Libraries..."
mkdir -p libs

# Download WinPcap Developer Pack (WpdPack)
wget https://www.winpcap.org/install/bin/WpdPack_4_1_2.zip -O WpdPack.zip

# Unzip only the x64 libraries we need
unzip -j WpdPack.zip WpdPack/Lib/x64/Packet.lib -d libs/
unzip -j WpdPack.zip WpdPack/Lib/x64/wpcap.lib -d libs/

# MinGW (GNU) sometimes prefers the 'lib' prefix for linking
cp libs/Packet.lib libs/libPacket.a
cp libs/wpcap.lib libs/libwpcap.a

rm WpdPack.zip

echo "[+] Libraries ready in 'libs/'"
ls -l libs/
