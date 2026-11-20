#!/usr/bin/env bash
# End-to-end Secure Boot test (Ubuntu/Debian host). Builds two Ubuntu-style
# test images from the distribution's signed shim + GRUB and a tampered EFI
# binary, writes a stick image with quiver, and boots it in QEMU with OVMF
# Secure Boot firmware enrolled with Microsoft's keys.
#   needs: xorriso qemu-system-x86 ovmf mtools, and apt-get download access
# Runs twice: ISO-backed mode (default) and extract mode. Expected in both:
# image A prints QUIVER-MARKER-A, image B prints QUIVER-MARKER-B, and the
# tampered binary is refused with "bad shim signature". The menu must also
# report "Secure Boot: ON". Exits non-zero if any expectation is not met.
set -euo pipefail
QUIVER=${QUIVER:-quiver}
W=$(mktemp -d); trap 'rm -rf "$W"' EXIT; cd "$W"
apt-get download shim-signed grub-efi-amd64-signed >/dev/null
for d in *.deb; do dpkg-deb -x "$d" x; done
X=x/usr/lib
mk() { d=src-$1; mkdir -p $d/EFI/BOOT $d/boot/grub $d/.disk
  cp $X/shim/shimx64.efi.signed.latest $d/EFI/BOOT/BOOTX64.EFI
  cp $X/grub/x86_64-efi-signed/grubx64.efi.signed $d/EFI/BOOT/grubx64.efi
  cp $X/shim/mmx64.efi $d/EFI/BOOT/; echo "Test $1" > $d/.disk/info
  printf 'echo "QUIVER-MARKER-%s root=$root"\nsearch --no-floppy --set=f -l %s\necho "label-search found=$f"\nsleep 2\nhalt\n' "$3" "$2" > $d/boot/grub/grub.cfg
  xorriso -as mkisofs -quiet -R -J -V "$2" -o $1.iso $d 2>/dev/null; }
mk alpha TEST_ALPHA A; mk bravo TEST_BRAVO B
cp $X/grub/x86_64-efi-signed/grubx64.efi.signed tampered.efi
printf '\xff' | dd of=tampered.efi bs=1 seek=200000 conv=notrunc 2>/dev/null
ACCEL=tcg; [ -w /dev/kvm ] && ACCEL=kvm
FAIL=0
boot() { # image slot expected-pattern
  cp "$1" t.img; "$QUIVER" menu --disk t.img --default "$2" --timeout 1 --yes >/dev/null
  cp /usr/share/OVMF/OVMF_VARS_4M.ms.fd vars.fd
  timeout 240 qemu-system-x86_64 -machine q35,smm=on,accel=$ACCEL -global driver=cfi.pflash01,property=secure,value=on \
    -m 1024 -display none -no-reboot -monitor none -serial file:s.log \
    -drive if=pflash,format=raw,unit=0,file=/usr/share/OVMF/OVMF_CODE_4M.secboot.fd,readonly=on \
    -drive if=pflash,format=raw,unit=1,file=vars.fd \
    -drive if=none,id=stick,format=raw,file=t.img -device qemu-xhci -device usb-storage,drive=stick,removable=on || true
  log=$(tr -d '\033' < s.log)
  got=$(grep -aoE 'QUIVER-MARKER-[A-Z] root=[a-z0-9,]+|bad shim signature' <<<"$log" | sort -u | tr '\n' ' ')
  if grep -aqE "$3" <<<"$log" && grep -aq 'Secure Boot: ON' <<<"$log"; then
    echo "  PASS slot $2: $got"
  else
    echo "  FAIL slot $2: expected /$3/ and 'Secure Boot: ON', got: ${got:-nothing}"
    FAIL=1
  fi
}
echo "ISO-backed mode (A, B on their ISO partitions; tampered extracted):"
"$QUIVER" build --disk iso.img --size 400M --yes alpha.iso bravo.iso tampered.efi >/dev/null
boot iso.img 2 'QUIVER-MARKER-A root=hd0,gpt3'
boot iso.img 4 'QUIVER-MARKER-B root=hd0,gpt5'
boot iso.img 6 'bad shim signature'
echo "Extract mode:"
"$QUIVER" build --disk ext.img --size 400M --mode extract --yes alpha.iso bravo.iso tampered.efi >/dev/null
boot ext.img 2 'QUIVER-MARKER-A root=hd0,gpt2'
boot ext.img 3 'QUIVER-MARKER-B root=hd0,gpt3'
boot ext.img 4 'bad shim signature'
exit $FAIL
