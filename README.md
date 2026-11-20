# quiver

Multi-image UEFI boot sticks that **keep Secure Boot enabled** and contain **no binary blobs**.

quiver puts any number of Linux, Windows, WinPE and EFI-tool images onto one USB stick and gives you a boot menu, like Ventoy. Unlike Ventoy, it does not ask you to disable Secure Boot or enroll a third-party key, and it ships no pre-compiled boot code. Every executable that runs at boot is an unmodified, vendor-signed binary taken from your own images. quiver itself contributes only filesystem layout and a short, plain-text GRUB configuration.

Version 1.1.1 · Go 1.24, standard library only · Linux and Windows · x86-64 UEFI

---

## Contents

1. [Why not Ventoy](#1-why-not-ventoy)
2. [How it works](#2-how-it-works)
3. [Quick start](#3-quick-start)
4. [Commands](#4-commands)
5. [Supported images and write modes](#5-supported-images-and-write-modes)
6. [Image fixups (what quiver changes, and why)](#6-image-fixups)
7. [Security model](#7-security-model)
8. [Verification and tamper evidence](#8-verification-and-tamper-evidence)
9. [Auditing and reproducible builds](#9-auditing-and-reproducible-builds)
10. [Testing performed](#10-testing-performed)
11. [Limitations](#11-limitations)
12. [Troubleshooting](#12-troubleshooting)
13. [On-disk format reference](#13-on-disk-format-reference)

---

## 1. Why not Ventoy

Ventoy boots an ISO file directly from an exFAT partition. To do that, it loads its own UEFI driver, which presents the ISO file to the firmware as a disk. That driver and several other components ship as pre-built binaries.

The driver is not signed by anyone your firmware trusts. So with Ventoy, Secure Boot must either be disabled, or Ventoy's own key must be enrolled into MOK on every machine. Enrolling the key means trusting whatever that key ever signs.

In a managed environment, both options are hard to defend.

Booting an arbitrary ISO *file* under stock Secure Boot is not possible without some such trust extension. The firmware only runs loaders signed by a key in its `db`, and each distribution's shim only trusts that distribution's kernels.

quiver therefore makes the other trade:

| | Ventoy | quiver |
|---|---|---|
| Secure Boot | must be disabled, or Ventoy key enrolled via MOK | stays on, no enrollment |
| Code that runs at boot | Ventoy's binaries | only vendor-signed binaries from your images |
| Prebuilt binaries in source | yes | none |
| Adding an image | copy the ISO file to the stick | `quiver add` (writes it into new partitions) |
| Large ISOs (files > 4 GiB) | yes | yes (ISO-backed mode, §5) |
| Shared storage on the stick | yes (exFAT) | yes (optional exFAT data partition) |
| Changes to host NVRAM | — | none (shim fallback is removed, see §6) |
| Tamper evidence | none | per-file SHA-256 lists + stick fingerprint |
| Legacy BIOS boot | yes | no (UEFI only) |

The cost is convenience: you add and remove images with a command rather than a file copy.

---

## 2. How it works

```
USB stick (GPT, protective MBR without boot code)
├── partition 1  "QUIVER MENU"   FAT32 EFI System Partition
│     /EFI/BOOT/BOOTX64.EFI     shim     ─┐ copied byte-for-byte from one of
│     /EFI/BOOT/grubx64.efi     GRUB     ─┤ your images (the "menu donor"),
│     /EFI/BOOT/mmx64.efi       MokMgr   ─┘ e.g. Ubuntu's, signed by MS/Canonical
│     /EFI/BOOT/grub.cfg  (+ copies at /boot/grub, /EFI/ubuntu, /EFI/debian)
│     /.quiver/manifest.json, files.sha256, README.txt
├── partition 2  "QV <title>"     FAT32: boot files of a Linux image + /.quiver/   ┐ ISO-backed
├── partition 3  "QV-ISO <title>" the original ISO, byte-for-byte (ISO 9660)     ┘ (Linux)
├── partition 4  "QV <title>"     FAT32: all files of a Windows image + /.quiver/   extracted
├── …
└── partition N  "QUIVER DATA"    exFAT shared storage (optional)
```

The boot sequence:

1. The firmware starts `\EFI\BOOT\BOOTX64.EFI` on partition 1. That is the donor's shim, signed by the Microsoft UEFI CA, and the firmware verifies it against `db`.
2. shim starts the donor's GRUB, which is signed by the distribution's key embedded in shim. GRUB runs in Secure Boot lockdown mode and reads `grub.cfg`.
3. Each menu entry does two things and nothing else:
   ```
   search --no-floppy --fs-uuid --set=root 1a2b-3c4d
   chainloader /EFI/BOOT/BOOTX64.EFI
   ```
4. GRUB asks shim to verify the chosen image's loader against `db`, `dbx`, MOK and SBAT. A Linux image's own shim passes because it is Microsoft-signed. Windows `bootmgfw.efi` passes because it is signed by Microsoft's Windows CA. A tampered or unsigned loader is refused.
5. From there each image boots exactly as it would from its own USB stick. For an ISO-backed image, its GRUB is redirected to the ISO partition next to it and reads its own `grub.cfg`, kernel and initrd from there. The live system then finds its media by the ISO's original label, just as on a `dd`-written stick.

Why GRUB chainloading is safe here: the signed GRUB never loads anything it has not verified through shim. The menu configuration can only choose *which* signed loader starts, never *what code* runs.

---

## 3. Quick start

Download the binary for your platform from the [latest release](https://github.com/klye-guy/Quiver/releases/latest) and check it (§9, *Releases*), or build it yourself.

**Linux** (run as root)

```sh
sudo ./quiver list-disks                       # find the stick, e.g. /dev/sdb
./quiver inspect ubuntu-24.04.iso Win11_24H2.iso   # optional dry run, writes nothing
sudo ./quiver build --disk /dev/sdb ubuntu-24.04.iso Win11_24H2.iso memtest.efi

# same, plus an exFAT partition for shared files using all remaining space
sudo ./quiver build --disk /dev/sdb --data rest ubuntu-24.04.iso Win11_24H2.iso
```

**Windows** (from an elevated PowerShell or Command Prompt)

```powershell
.\quiver.exe list-disks                         # find the stick, e.g. \\.\PhysicalDrive2
.\quiver.exe build --disk 2 ubuntu-24.04.iso Win11_24H2.iso
```

`build` asks you to type the target path to confirm. It then writes everything and prints a summary and a **fingerprint**. Record the fingerprint (§8).

Boot the target machine from the stick using the firmware's one-time boot menu (often F12, F9 or Esc). Secure Boot can stay on.

To produce an image file instead of writing a disk (for example to test in a VM or archive a build):

```sh
./quiver build --disk stick.img --size 32G ubuntu.iso windows.iso
# later: dd if=stick.img of=/dev/sdX bs=4M conv=fsync   (or Rufus "DD mode")
```

---

## 4. Commands

`TARGET` (`--disk`) is a whole disk or an image file:

- **Linux:** `/dev/sdX` or `/dev/disk/by-id/...`
- **Windows:** `\\.\PhysicalDriveN`, `PhysicalDriveN`, `diskN` or `N`

Partitions are refused. Flags may appear before or after the image arguments.

### `list-disks [--all] [--json]`

Lists whole disks with size, bus, removable flag and model. Disks holding the running system are marked and are always refused for writing.

### `inspect IMAGE... [--json] [--checksums F] [--require-signed]`

Analyses images and writes nothing. For each image it shows:

- SHA-256 and format: ISO 9660 with Rock Ridge or Joliet, UDF, FAT image, or EFI application
- kind of image and volume label
- the Authenticode signer and trust anchor of each UEFI loader, and whether the signature is intact
- whether the image can supply the menu (it can if it has a signed shim and GRUB)
- every fixup that would be applied
- the resulting partition size

Exits non-zero if an image cannot be written or fails policy.

### `build --disk TARGET [options] IMAGE...`

Erases the target and writes a new stick. Every image is read, hashed, checked and planned *before* the first byte is written. The partition table is written *last*, so an interrupted run leaves a blank disk rather than a half-valid one.

| Option | Meaning |
|---|---|
| `--size 16G` | create an image file of this size instead of using a disk |
| `--title FILE=TITLE` | menu title for an image (repeatable; default: file name) |
| `--mode auto\|extract\|iso` | how images are written (§5); default `auto` |
| `--data SIZE\|rest` | add an exFAT data partition of SIZE (e.g. `64G`), or using all space left after the images |
| `--data-label L` | data partition label, up to 11 characters (default `QUIVER-DATA`) |
| `--menu-from IMAGE` | take the menu's shim and GRUB from this image (it need not be written to the stick) |
| `--timeout N` | menu timeout in seconds; default `-1` waits for a choice |
| `--default SLOT` | entry booted when the timeout expires |
| `--password-file F` / `--password-env VAR` | require a password to boot any image entry (§7) |
| `--user NAME` | menu superuser name when a password is set (default `admin`) |
| `--checksums F` | `SHA256SUMS`-style file of expected image hashes (GNU or BSD format; repeatable) |
| `--require-checksums` | refuse any image not listed in a `--checksums` file |
| `--require-signed` | refuse any image whose UEFI loader lacks a valid signature |
| `--seed STRING` | derive all GUIDs, volume IDs and timestamps from STRING, for bit-for-bit reproducible output |
| `--allow-fixed` | permit writing to a non-removable disk |
| `--yes` | skip the confirmation prompt (for scripts) |

### `add --disk TARGET [--title T] [--mode M] [policy flags] IMAGE`

Writes one more image into the first free gap that fits, then rewrites the menu. An ISO-backed image needs one gap large enough for both of its partitions.

### `remove --disk TARGET SLOT`

Removes the image whose boot partition is `SLOT` (see `list`), including its ISO partition in ISO-backed mode. The freed space is reused by later `add`s. The removed partition's first MiB is zeroed so no OS will mount stale data.

### `data --disk TARGET [--size N] [--label L]`  /  `data --disk TARGET --remove`

Creates the exFAT data partition on an existing stick, in the largest free area.
- With `--size`, it sits at the end of that area, so the space before it stays available for future images.
- Without `--size`, it uses the whole area.
- `--remove` deletes the partition **and every file on it**.

A stick has at most one data partition.

### `list --disk TARGET [--json]`

Shows images, menu donor, password state and free space. `--json` prints the full manifest.

### `verify --disk TARGET [--expect FINGERPRINT]`

Re-hashes every file on every partition and compares it with the checksum lists. It also cross-checks the manifest, GPT GUIDs and volume IDs, and confirms the menu loaders still carry intact signatures.

It reports modified, missing and *unexpected* files, then computes the stick fingerprint. With `--expect`, it fails unless the fingerprint matches.

### `menu --disk TARGET [options]`

Rewrites the menu partition without touching the images. Options:

- `--timeout`, `--default SLOT`, `--user`
- `--password-file` / `--password-env`, or `--no-password`
- `--title SLOT=TITLE` (repeatable)
- `--menu-from IMAGE` to swap the menu's shim and GRUB, for example after an SBAT revocation
- `--repair` to rebuild the manifest and menu from the metadata each image partition carries, if the menu partition is damaged

---

## 5. Supported images and write modes

### Write modes

FAT32 is the only filesystem every UEFI firmware can read, and it cannot store a file of 4 GiB or more. quiver therefore has two ways to write an image.

**ISO-backed mode** (`iso`) is used by default for Linux ISOs that boot through GRUB.
- The original ISO is written **byte-for-byte** to its own partition, so no file size limit applies.
- A small FAT32 boot partition holds only the ISO's `/EFI` files: its signed shim and GRUB, unmodified.
- quiver adds GRUB configuration stubs on that boot partition that point GRUB at the ISO partition. Signed GRUB builds read ISO 9660 natively, so GRUB loads the image's own `grub.cfg`, kernel and initrd straight from the ISO.
- The live system's initramfs then finds its media exactly as it does on a `dd`-written stick: by the ISO's original volume label, or by scanning block devices.

Consequences of ISO-backed mode:
- no label rewrites, no symlink losses and no file renames; the image is untouched
- the ISO partition's SHA-256 equals the vendor's published ISO checksum, and `verify` checks exactly that
- Debian's installer works, because it finds ISO 9660 media
- costs one extra partition per image (≈34 MiB boot partition + the ISO)

**Extract mode** (`extract`) copies the image's files onto one FAT32 partition, with the fixups in §6. It is used for:
- Windows and WinPE media. Windows' boot manager can only read FAT, so oversized `install.wim` files are split into `.swm` parts, which Windows Setup supports natively.
- images whose boot chain isn't GRUB (for example systemd-boot)
- UDF sources, FAT images and bare EFI applications

`--mode auto` (the default) picks ISO-backed mode whenever the image qualifies, and extract mode otherwise. `--mode extract` or `--mode iso` forces a mode; `inspect` shows which mode an image gets and why.

### The boot menu

The menu detects the Secure Boot state at boot time and shows it as the first line:

```
 Secure Boot: ON   -  signed images only  (select: firmware settings)
 Ubuntu 24.04
 Arch Linux  [unsigned: blocked while Secure Boot is on]
 Windows 11
 Reboot
 Power off
```

With Secure Boot off, the first line reads `Secure Boot: OFF  -  all images can boot`, and unsigned entries read `[unsigned: OK, Secure Boot is off]`. Selecting the status line opens the UEFI firmware settings, where Secure Boot can be switched.

Detection uses GRUB's own `$lockdown` variable, which signed GRUB sets only when Secure Boot is enforcing. Starting an unsigned entry with Secure Boot on is harmless: shim refuses it and you return to the menu.

**Unsigned-only sticks.** The menu always runs a vendor-signed shim and GRUB. If none of your images has them, pass `--menu-from` with any recent Ubuntu or Debian ISO at build time. Only its three loader files are copied, and later `add`/`remove`/`menu` runs reuse them, so you never need that ISO again. If that shim or GRUB is ever revoked, swap in a newer one with `quiver menu --menu-from`.

### Data partition

`--data` (at build time) or `quiver data` (later) adds an **exFAT** partition named `QUIVER DATA` for shared files.
- It is read-write on Windows, macOS and Linux without extra software, and has no 4 GiB limit.
- quiver formats it itself, following Microsoft's published exFAT specification.
- Its contents belong to you: `verify` checks that the partition and its filesystem are intact, but does not hash your files.

To keep Windows tidy, boot and ISO partitions of non-Windows images are flagged "no drive letter", so when the stick is plugged into a Windows PC only the data partition (and any Windows image partitions) get a drive letter. Windows image partitions keep theirs because Windows Setup needs one to find its installation files.

### Image types

| Kind | Detected by | Notes |
|---|---|---|
| Ubuntu family (casper) | `/casper` | Ubuntu, Kubuntu, Mint, Pop!_OS, … |
| Debian live (live-boot) | `/live/filesystem.squashfs` | Debian live, Kali live, Tails-style |
| Fedora / RHEL family (dracut) | `/LiveOS`, `/images/pxeboot` | Fedora, RHEL, Rocky, Alma; `CDLABEL=`/`LABEL=` rewritten |
| Arch (archiso) | `/arch` | `archisolabel=` rewritten |
| openSUSE | `/boot/x86_64/loader` | |
| Debian installer | `/install.amd` | works in ISO-backed mode; see §11 for extract mode |
| Windows Setup | `/sources/boot.wim` + `install.wim/esd/swm` | `install.wim` > 4 GiB is split into `.swm` parts |
| WinPE / rescue media | `/sources/boot.wim` | |
| EFI applications | a bare `.efi` file | placed at `\EFI\BOOT\BOOTX64.EFI` |
| FAT images | `.img` with a FAT boot sector | contents copied |

Image formats read:

- **ISO 9660** with the Rock Ridge (names, symlinks, deep-directory relocation) and Joliet extensions, including multi-extent files
- **UDF** 1.02–2.01 with a single type-1 partition (all Windows media)
- **El Torito** UEFI boot images: if `\EFI\BOOT\BOOTX64.EFI` exists only inside the ISO's embedded FAT boot image, its files are merged in
- **FAT12/16/32** images

An image needs an **x86-64 UEFI loader** (`\EFI\BOOT\BOOTX64.EFI`). BIOS-only images are refused.

**Which images run under Secure Boot** is decided by the firmware, not quiver. `inspect` shows each loader's trust anchor:

- **Microsoft UEFI CA 2011 / 2023 (third-party):** most Linux shims. Requires the third-party CA in `db`. Many business laptops ship it enabled. Some "Secured-core" PCs ship it *disabled* (firmware setting "Allow Microsoft 3rd Party UEFI CA" or similar).
- **Microsoft Windows Production PCA 2011 / Windows UEFI CA 2023:** Windows boot managers. Machines that have applied the BlackLotus mitigations (KB5025885) revoke PCA 2011-signed boot managers; use current Windows media signed with the 2023 CA there.
- **Unsigned:** boots only on machines with Secure Boot off. The menu says which applies to the machine in front of you (see "The boot menu" below). Use `--require-signed` to keep such images off the stick.

---

## 6. Image fixups

In **extract mode**, quiver copies each image's files onto FAT32. A few things cannot be copied verbatim, and each change is recorded in the image's `/.quiver/image.json` and shown by `inspect`.

In **ISO-backed mode**, the ISO itself is never changed. Only items 1 and 7 apply to its boot partition, plus a redirect stub. The stub sends GRUB to the ISO partition next to it.
- It finds that partition on the same disk as the boot partition GRUB is running from (`$root`, or `$cmdpath`), so identical ISOs never get mixed up.
- It falls back to the ISO's GRUB volume UUID only if that fails.

**No EFI executable is ever modified.** The fixups below touch only plain-text configuration files, add new configuration files, or rearrange data.

1. **shim fallback removed.** `\EFI\BOOT\fbx64.efi` is not copied. When shim runs from the removable-media path and finds `fbx64.efi`, it runs it, and that fallback writes new boot entries into the *host machine's* NVRAM. On a stick plugged into other people's computers that is unwanted. Booting is unaffected.

2. **Symbolic links.** FAT has none.
   - A link to a file becomes a copy of that file.
   - A link to a directory, or to nothing inside the image, is omitted. Ubuntu's `ubuntu -> .` loop is the typical case.

3. **Volume labels → filesystem UUID.** Some distributions find their root filesystem by the ISO's volume label, as in `root=live:CDLABEL=Fedora-WS-Live-41`, `inst.stage2=hd:LABEL=…`, `archisolabel=…` or GRUB's `search -l '…'`.
   - FAT labels are limited to 11 characters, so those references are rewritten to the new partition's FAT volume UUID, which every one of those tools also accepts.
   - Only `.cfg`/`.conf` files under `/boot`, `/EFI` and `/loader` are touched.
   - The rewrite matches only the exact label, in those parameter positions.

4. **GRUB prefix pinning.** A signed GRUB has a compiled-in prefix, for example Ubuntu's `/EFI/ubuntu`. When that directory doesn't exist on the boot partition, GRUB falls back to searching *every disk* for its configuration. With several images on one stick, it then loads the wrong one or fails.

   quiver reads the prefix from the image's GRUB binary and adds a 9-line `/EFI/<vendor>/grub.cfg` stub. The stub pins `root` to the image's own partition UUID and then sources the image's original `/boot/grub/grub.cfg`. This was verified necessary in testing (§10): without the stub, a second Ubuntu-style image dropped to a `grub>` prompt.

5. **Windows `install.wim` > 4 GiB** is split into `install.swm`, `install2.swm`, … (≤ 4000 MiB each), the format `DISM /Split-Image` produces and Windows Setup reads natively.
   - Resources are copied byte-for-byte: nothing is decompressed or re-compressed, and all SHA-1 hashes stay valid.
   - The header and table layout matches wimlib's `wimsplit`.
   - Solid/ESD archives larger than 4 GiB cannot be split and are refused; convert them with `DISM /Export-Image` first.

6. **File names** that FAT cannot hold (`" * : < > ? \ |`, trailing dots/spaces) are changed to `_` and listed. Names that collide case-insensitively are refused.

7. **Metadata added:** `/.quiver/image.json` and `/.quiver/files.sha256` on every image partition.

---

## 7. Security model

### What quiver guarantees

- **No boot-time code of its own.** Every executable on the stick is an image vendor's original binary; quiver only adds data and text configuration. The protective MBR and FAT boot sectors carry no x86 code (they are zero-filled).
- **Secure Boot is never weakened.** Nothing is enrolled into MOK or `db`, and nothing requires turning Secure Boot off. Every chainloaded binary is verified by shim and the firmware, including `dbx` and SBAT revocations.
- **No NVRAM writes on host machines** (shim fallback removed).
- **Integrity checks before writing:**
  - Images are SHA-256 hashed and can be pinned to vendor checksums (`--checksums`, `--require-checksums`).
  - Each loader's Authenticode signature is checked: the image digest is recomputed and the PKCS#7 signer signature verified, with `--require-signed` available.
- **Safe device handling:**
  - Partitions are refused, and so are disks holding the running system.
  - Fixed disks need `--allow-fixed`.
  - On Linux the disk is opened `O_EXCL`, which fails if anything on it is mounted.
  - On Windows every volume on the disk is locked and dismounted first.
  - Explicit confirmation is required.
- **Tamper evidence:** per-file SHA-256 lists and a stick fingerprint (§8).

### What it does not guarantee

- **The menu configuration is not signed.** `grub.cfg` is plain text on an unencrypted FAT partition. Someone with the stick can edit it, but can only point entries at loaders that still have to pass Secure Boot verification. They cannot make unsigned code run on a Secure Boot machine. `verify` detects the edit.
- **The menu password is an access control, not encryption.** `--password-file` makes GRUB require a username and password before booting any image entry, which stops casual use of an unattended stick.
  - The PBKDF2-SHA512 hash (100,000 iterations, 64-byte random salt) is stored on the stick, so choose a strong password.
  - Anyone who can modify the stick can remove the password; `verify` detects that.
  - The Secure Boot status line (firmware settings), reboot and power-off stay unrestricted.
- **Images are trusted as given.** quiver verifies that what you supplied is what gets written and booted, and that the loaders are signed. It does not vet the operating systems themselves. Pin images to vendor checksums.
- **The menu donor matters.**
  - The donor's shim and GRUB run first on every boot. They come from an image you chose; prefer a current Ubuntu or Debian release.
  - If its SBAT generation is later revoked, firmware will refuse the menu. Replace it with `quiver menu --menu-from <newer ISO>`.
  -
- **Volume ID search scope.** Menu entries locate their partition by FAT volume UUID across all disks. A deliberately crafted disk with a matching UUID could be selected instead, but its loader would still have to pass Secure Boot. Volume IDs are random unless `--seed` is used.

### Threats considered

| Threat | Mitigation |
|---|---|
| Malicious/compromised tool binary | stdlib-only Go source, reproducible builds (§9), no network access, no embedded binaries |
| Wrong or modified ISO | SHA-256 pinning against vendor checksums |
| Unsigned or tampered loader | Authenticode check at build; shim/firmware enforcement at boot (tested, §10) |
| Stick modified after build | `verify --expect <fingerprint>` |
| Writing to the wrong disk | whole-disk only, system-disk refusal, removable/USB requirement, typed confirmation |
| Host NVRAM pollution | shim fallback removed |

---

## 8. Verification and tamper evidence

Every partition has `/.quiver/files.sha256` in standard `sha256sum` format, listing every file on that partition except the list itself. You can check a partition with nothing but coreutils:

```sh
cd /media/user/QUIVER2 && sha256sum -c .quiver/files.sha256
```

The **fingerprint** printed by `build`, `add`, `remove` and `menu` is a SHA-256 over the disk GUID, the checksum list of each partition, and the volume IDs. It therefore covers every byte of every file and the stick's identity.

1. Record the fingerprint when you prepare a stick, for example in your asset or ticketing system.
2. Later, check it:

```sh
sudo ./quiver verify --disk /dev/sdb --expect 2fa7f6723b69dffb…
```

`verify` fails on:

- any modified, missing or *added* file
- a GPT/manifest mismatch
- a volume ID mismatch
- a menu loader whose signature is no longer intact
- a fingerprint that differs from `--expect`

---

## 9. Auditing and reproducible builds

### Source layout (about 8,000 lines of Go, standard library only)

| Package | Purpose |
|---|---|
| `internal/iso9660` | ISO 9660 + Rock Ridge + Joliet + El Torito reader |
| `internal/udf` | UDF reader |
| `internal/fat` | FAT12/16/32 reader; deterministic FAT32 builder |
| `internal/exfat` | exFAT formatter for the data partition |
| `internal/gpt` | GPT + protective MBR reader/writer |
| `internal/wim` | WIM → `.swm` splitter |
| `internal/pe` | PE/COFF parsing, Authenticode digest + PKCS#7 verification, SBAT |
| `internal/image` | image loading, classification, fixups |
| `internal/menu` | `grub.cfg` generation, GRUB PBKDF2 hashing |
| `internal/stick` | layout, build/add/remove/menu/verify, manifest, fingerprint |
| `internal/blockdev` | Linux and Windows raw-disk access with safety checks |
| `cmd/quiver` | command-line interface |

The only third-party code involved is the Go toolchain. `go.mod` has no dependencies.

### Releases

Every push to `main` is released automatically by `.github/workflows/release.yml`, but only after two gates pass:
1. the unit tests (cross-checked against `fsck.fat`, `sgdisk`, `fsck.exfat` and wimlib), plus `gofmt` and `go vet` for Linux and Windows
2. the QEMU + OVMF Secure Boot boot test (`test/secureboot-e2e.sh`), which fails the run if any image doesn't boot or the tampered binary isn't refused

Each release carries:
- binaries for Linux and Windows (amd64, arm64)
- the source tarball (`git archive` of the released commit)
- `SHA256SUMS` and `BUILDINFO.txt` (commit, Go version, exact build command)
- signed [build provenance](https://docs.github.com/en/actions/security-for-github-actions/using-artifact-attestations) for every binary, linking it to the commit and workflow run that built it

**Version numbers.** `var version` in `cmd/quiver/main.go` is the base. The first release of a base gets that number, and later pushes continue the patch number (1.1.1, 1.1.2, 1.1.3, …). To start a new series, change the base in the source (e.g. to `1.2.0`). The version is stamped into the binary at build time, so `quiver version` always matches the release tag.

**Verifying a download:**

```sh
sha256sum -c SHA256SUMS --ignore-missing                      # file integrity
gh attestation verify quiver-linux-amd64 --repo klye-guy/Quiver   # built by this repo's workflow, from the stated commit
```

The workflow's third-party actions are pinned to full commit SHAs, and Dependabot proposes updates weekly.

### Rebuilding the release binaries

```sh
# use the Go version from BUILDINFO.txt; VER is the release version
CGO_ENABLED=0 GOOS=linux   GOARCH=amd64 go build -trimpath -ldflags "-s -w -buildid= -X main.version=$VER" -o quiver-linux-amd64 ./cmd/quiver
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags "-s -w -buildid= -X main.version=$VER" -o quiver-windows-amd64.exe ./cmd/quiver
sha256sum quiver-*        # compare with SHA256SUMS
```

The same Go version, flags and version string produce identical binaries. `go version -m <binary>` shows what is embedded.

### Reproducible sticks

With `--seed`, two `build` runs with the same images and options produce byte-identical stick images. This was verified by hashing (§10). An auditor can rebuild an image file from the same ISOs and seed and compare hashes, or compare its fingerprint with the one recorded for a deployed stick.

### Running the tests

```sh
go test ./...                    # unit tests; some use fsck.fat, sgdisk, wimlib, xorriso, genisoimage if installed
QUIVER_TEST_SHIM=/usr/lib/shim/shimx64.efi.signed.latest go test ./...   # also runs the Authenticode tests
QUIVER=./quiver test/secureboot-e2e.sh   # QEMU + OVMF Secure Boot boot test (Ubuntu host); exits non-zero on failure
```

---

## 10. Testing performed

Test environment: Ubuntu 24.04 host, QEMU 8.2 with OVMF `OVMF_CODE_4M.secboot.fd` and `OVMF_VARS_4M.ms.fd` (Secure Boot enabled; Microsoft KEK/db enrolled). Test images were built from Ubuntu's own signed `shim-signed 15.8` and `grub-efi-amd64-signed 2.12`.

| Test | Result |
|---|---|
| Firmware → donor shim (MS UEFI CA 2011) → Canonical GRUB → menu | menu displayed with Secure Boot on |
| **ISO-backed:** ISO with a 4.6 GiB file (Ubuntu HD GRUB build) | booted with Secure Boot on; GRUB redirected to the ISO partition and listed the file at its full 4,823,449,600 bytes; the original `CDLABEL=` label resolves to the ISO partition |
| **ISO-backed:** same with GRUB's CD build (`gcdx64`), and a small ISO | both booted from their own ISO partitions |
| **ISO-backed:** two ISOs with an identical volume UUID on one stick | each booted its own ISO partition (the redirect locates the partition from GRUB's `$root`, not the UUID) |
| **ISO-backed:** partition lookup disabled (forces the volume-UUID fallback) | booted the right ISO; `verify` reported the edited stub |
| **ISO-backed:** `verify` | each ISO partition's SHA-256 equals its source file |
| **Extract mode:** chainload image 1 (shim + GRUB, HD build) | booted; GRUB pinned to its own partition; label search and `CDLABEL=` rewritten to UUID |
| Chainload image 2 with a second Ubuntu-style image present | booted its own config, not image 1's |
| Same, with the pinning stub removed (negative control) | GRUB dropped to `grub>`; `verify` reported the missing file |
| Image using GRUB's CD build (`gcdx64`) | booted from its own partition |
| Tampered signed binary | refused at boot: `error: bad shim signature` |
| Menu password: wrong / correct | `access denied` / booted |
| Menu Secure Boot status, with Secure Boot on and off | status line and unsigned-entry notes match the state; the unsigned entry is refused when on and starts when off |
| Stick with only unsigned images, built with `--menu-from` | menu works; unsigned entries boot with Secure Boot off |
| FAT32 output, 512 and 4096-byte sectors | `fsck.fat -n` clean; mtools reads all files; checksum lists pass `sha256sum -c` |
| GPT output | `sgdisk -v`: no problems; backup header fallback works |
| WIM split, multi-image WIM | `wimverify` passes; `wimapply` of each image is byte-identical |
| UDF image (genisoimage, 1.3 GB file spanning several extents) | contents read correctly |
| Windows-layout UDF ISO with oversized `install.wim` | split into `.swm`; `wimverify` passes |
| El Torito-only EFI loader | merged from the boot image |
| Authenticode | MS-signed shim, dual-signed shim and Canonical GRUB verify; one flipped byte is detected |
| `--seed` builds | two runs byte-identical |
| add / remove / freed-gap reuse / menu edit / verify / repair, both modes mixed on one stick | as specified |
| exFAT data partition (64 MiB, 700 MiB, 40 GiB; 512 and 4096-byte sectors) | `fsck.exfat` clean |
| exFAT data partition in use | the Linux exFAT driver (exfat-fuse) mounts it; a 200–300 MB file and directories round-trip; `fsck.exfat` clean afterwards; `verify` passes with user files present |
| data partition create / remove / recreate; `remove` refuses the data slot | as specified |
| Windows build | compiles and passes `go vet` for `GOOS=windows` |

**Not tested in this environment:**
- **Real hardware.** No physical USB writes were made: the Linux block-device path was exercised on a loop device, and the Windows raw-disk path (`\\.\PhysicalDriveN`, volume lock and dismount) is compile-checked only.
- **Real vendor ISOs.** Test images reproduce the layouts of real ISOs but are not those ISOs; no actual Windows media was available.
- **Booting a real live system from an ISO partition.** The test images stop in GRUB, so Linux initramfs media discovery from an ISO partition (casper, live-boot, dracut, archiso) was not exercised. Those tools find their media the same way on a `dd`-written stick, which is the design's basis, but confirm on your images.
- **Fedora/RHEL GRUB builds** (which use `/EFI/BOOT/grub.cfg` and `$cmdpath`) were not available to test.
- **Windows and macOS mounting the exFAT data partition.**

Before deploying, run `quiver inspect` on your actual images and test-boot one stick on representative hardware. Ventoy's per-distribution compatibility list took years to build; treat this as a 1.0.

---

## 11. Limitations

- **x86-64 UEFI only.** No legacy BIOS, no 32-bit UEFI, no ARM64 menu.
- **Files larger than 4 GiB:**
  - No limit for ISO-backed images.
  - In extract mode, files over 4 GiB cannot be stored, except Windows `install.wim`, which is split.
  - A Windows `install.esd` over 4 GiB cannot be split and is refused; convert it with `DISM /Export-Image`.
  - A non-GRUB image with a file over 4 GiB is also refused.
- **Images are written into their own partitions**, not stored as ISO files on a shared filesystem. You cannot drag an ISO onto the stick; use `quiver add`. Ventoy-style persistence files and loopback booting do not apply.
- **No persistence partitions** for live systems.
- **Debian's installer in extract mode** (netinst/DVD, forced with `--mode extract`) may ask for its installation media, because it searches for ISO 9660. Use the default ISO-backed mode instead.
- **The menu requires a shim + GRUB donor.** A stick containing only Windows images needs `--menu-from` with any recent Ubuntu or Debian ISO.
- **SBAT/DBX revocations** apply as designed. If a donor or image loader is revoked on a machine, that machine refuses it; refresh the image or donor.

---

## 12. Troubleshooting

| Symptom | Cause / fix |
|---|---|
| Stick not offered in the boot menu | The firmware may hide removable media; enable USB boot. The stick is UEFI-only. |
| `Security Violation` / `Verification failed` before the menu | The donor's shim is not trusted: the third-party CA is disabled in firmware, or the donor's SBAT is revoked. Enable "Microsoft 3rd-party UEFI CA" or rebuild with `--menu-from` a newer ISO. |
| `error: bad shim signature` on an entry | That image's loader is unsigned, tampered, or revoked on this machine. Expected Secure Boot behaviour. |
| Windows entry fails on a machine with BlackLotus mitigations | The media's boot manager is PCA 2011-signed; use current Windows media signed with the 2023 CA. |
| `has mounted filesystems` / `in use` | Unmount the stick's partitions (Linux) or close Explorer windows on it (Windows). |
| `access denied` on Windows | Run from an elevated prompt. |
| Menu damaged | `quiver menu --disk X --repair` rebuilds it from the image partitions. |

---

## 13. On-disk format reference

**Partition table.** GPT with 128 entries and a protective MBR (type `0xEE`, no boot code). Partitions are 1 MiB-aligned.

**Partition 1.** EFI System Partition type, named `QUIVER MENU`, FAT32, at least 128 MiB.

**Image partitions.** Microsoft Basic Data type, named `QV <title>`, FAT32, sized to content (rounded to 1 MiB). Slot number = GPT partition number. Non-Windows images carry the "no drive letter" and "hidden" attributes (bits 63 and 62).

**ISO partitions** (ISO-backed mode). Linux data type, named `QV-ISO <title>`, placed right after the image's boot partition. They contain the ISO byte-for-byte, and the tail up to the 1 MiB boundary is zeroed.

**Data partition.** Microsoft Basic Data type, named `QUIVER DATA`, exFAT. Cluster size follows Windows' defaults: 4 KiB up to 256 MiB, 32 KiB up to 32 GiB, 128 KiB above.

**FAT32 details:**
- OEM name `MSWIN4.1`
- 2 FATs
- data region 1 MiB-aligned
- cluster size chosen to minimise filesystem size
- long file names (VFAT) with Windows-compatible `~N` short names

**`/.quiver/manifest.json`** (menu partition):
- format version and tool version
- disk GUID and sector size
- menu settings (timeout, default slot, user, password hash)
- donor provenance: source image and its SHA-256, file hashes, signers, GRUB prefixes
- one `image` record per image partition
- the data partition (slot, GUID, label, exFAT serial), if any
- created/updated times

**`/.quiver/image.json`** (each image partition):
- slot, partition GUID, volume ID, title
- write mode; in ISO-backed mode also the ISO slot, partition GUID and GRUB UUID
- source name, SHA-256, size and format
- volume label and kind
- loader and stage-2 paths, hashes and signatures
- `menu_capable`
- fixups and warnings
- file count, bytes, added time

**`/.quiver/files.sha256`.** `sha256sum` format, paths relative to the partition root, sorted.

**Fingerprint:**

```
sha256( "quiver-fingerprint-v1\n"
        "disk <DISK-GUID>\n"
        "menu <sha256 of menu files.sha256>\n"
        "slot <n> <VOLUME-ID> <sha256 of slot files.sha256>\n" … )
```
