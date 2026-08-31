# Windows 11 on Proxmox — repeatable builds

Create a fully preconfigured Windows 11 VM without touching the installer, then
turn it into a template so every machine after the first takes about a minute.

## The shape of it

```
build-unattend-iso.sh   ──▶  a tiny ISO holding autounattend.xml + provision.ps1
create-vm.sh            ──▶  VM 120, boots, installs itself unattended  (~20 min, once)
switch-to-virtio.sh     ──▶  move the OS disk from AHCI to virtio-scsi  (~2 min, once)
make-template.sh        ──▶  sysprep + convert VM 120 to a template     (~5 min, once)
clone-vm.sh             ──▶  VM 121, 122, 123 …                         (~1 min each)

new-sandbox.sh          ──▶  next free ID in 900-949, linked clone, prints the IP
destroy-sandbox.sh      ──▶  throw one away
```

The first four run once. `clone-vm.sh` is the one you actually use.

## Prerequisites

Both scripts run **on a Proxmox node**, as root — `qm` is node-local.

1. **A Windows 11 ISO** on an ISO-capable storage (`local`, or the NAS). Get it
   from Microsoft's [Download Windows 11](https://www.microsoft.com/software-download/windows11)
   page and upload via the Proxmox UI: *Storage → ISO Images → Upload*.

2. **The virtio-win driver ISO.** `create-vm.sh --download-virtio` fetches it,
   or grab it yourself:
   ```sh
   curl -fLo /var/lib/vz/template/iso/virtio-win.iso \
     https://fedorapeople.org/groups/virt/virtio-win/direct-downloads/stable-virtio/virtio-win.iso
   ```

3. **swtpm**, which provides the TPM 2.0 device Windows 11 requires:
   ```sh
   apt install swtpm swtpm-tools
   ```

Confirm the edition name in your ISO matches `IMAGE_NAME` — a mismatch is the
most common reason an "unattended" install stops on the edition picker. Mount the
ISO and run:

```sh
dism /Get-WimInfo /WimFile:D:\sources\install.wim     # from Windows
7z l /path/to/win11.iso                                # or inspect from the node
```

## Usage

Copy this directory to the node first:

```sh
scp -r provision/windows11 root@PVE_HOST:/root/
ssh root@PVE_HOST
cd /root/windows11 && chmod +x *.sh
```

```sh
cd /root/windows11

# 1. Build the answer-file ISO. Prompts for the admin password.
COMPUTER_NAME=win11-base USERNAME=sandbox \
WINGET='Git.Git Microsoft.VisualStudioCode Mozilla.Firefox' \
  ./build-unattend-iso.sh

# 2. Create and boot the VM.
./create-vm.sh --vmid 120 --name win11-base \
               --unattend local:iso/unattend-win11-base.iso \
               --storage local-lvm --cores 4 --memory 8192 --disk 96

# --- open the console and press a key at "Press any key to boot from CD" ---
# --- then walk away for ~20 minutes ---

# 3. Move the OS disk onto virtio-scsi now that the guest has the driver.
#    Refuses to run if vioscsi is missing, and reverts if the VM does not return.
./switch-to-virtio.sh --vmid 120

# 4. Log in once, install anything else you want in every machine, then:
./make-template.sh --vmid 120

# 5. From here on:
./clone-vm.sh --template 120 --vmid 121 --name devbox
./clone-vm.sh --template 120 --vmid 122 --name buildbox --cores 8 --memory 16384
```

### Throwaway sandboxes

Once the template exists, this is the whole workflow:

```sh
./new-sandbox.sh                    # ~5s to clone, ~2min to a usable desktop
./destroy-sandbox.sh --list
./destroy-sandbox.sh --vmid 900
```

`new-sandbox.sh` takes a **linked clone**, which is why it is seconds rather than
minutes: only the blocks that differ from the template are stored. The clone
depends on the template's disk forever, which is the right trade for something
disposable and the wrong one for a machine you mean to keep -- pass `--full` for
that.

IDs come from a dedicated range (900-949 by default, `SANDBOX_ID_LO`/`_HI`).
That is not cosmetic: `provision/monit/pve-backup-check.py` skips the range, so
disposable machines do not set off the coverage alert every time you make one.
Without that, the check would cry wolf often enough that you would learn to
ignore it -- which is precisely the failure it exists to catch.

`destroy-sandbox.sh` is deliberately hard to misuse. It refuses anything outside
the range, anything without the `SANDBOX` description marker, and -- with no
override at all -- anything that is a template.

For a sandbox you reset repeatedly rather than recreate, snapshots beat cloning:

```sh
qm snapshot 900 clean          # right after first boot
qm rollback 900 clean          # seconds, allocates nothing
```

## The one manual step

Microsoft's boot image prints *"Press any key to boot from CD or DVD"* and waits
about five seconds. There is no unattend setting for it — it happens before any
answer file is read. Miss it and the VM drops to the UEFI shell; `qm reset <vmid>`
and try again.

This is the strongest argument for the template workflow: you press that key
exactly once, ever.

## Why the VM is configured the way it is

Windows 11 refuses to install without these, and each fails differently enough
to be worth naming:

| setting | without it |
|---|---|
| `--machine q35 --bios ovmf` | Setup refuses: Windows 11 requires UEFI |
| `--tpmstate0 …,version=v2.0` | Setup refuses: "This PC doesn't meet the requirements" |
| `--efidisk0 …,pre-enrolled-keys=1` | Secure Boot has no trusted keys; the signed bootloader is rejected |
| `--cpu host` | the `kvm64` default lacks SSE4.2/POPCNT and fails the CPU check |
| OS disk on `sata1`, not `scsi0` | Installing onto virtio-scsi finishes and then bluescreens INACCESSIBLE_BOOT_DEVICE — see below |
| `--balloon 0` | Windows reports nonsense memory until the balloon driver exists |

`autounattend.xml` also writes the `HKLM\SYSTEM\Setup\LabConfig` bypass keys.
They are redundant on this cluster — the VM has a real TPM and real Secure Boot —
and are kept only so the same ISO still works on a host without `swtpm`.

## Placement

Put the template and its clones on whichever node has the most spare cores and
RAM. A sandbox is 4 cores / 8 GiB by default, and a linked clone stores only the
blocks that differ from the template -- so the marginal disk cost of each extra
sandbox stays small until it diverges. RAM is the binding constraint, not disk.

Check what a node actually has free before committing to a size:

```sh
pvesh get /nodes
```

Pass `--storage <name>` to put the Windows disk somewhere other than
`local-lvm`. Prefer an SSD or NVMe pool: Windows installs and sysprep are
seek-heavy, and a spinning disk turns a five-minute build into a slow one.

## Customising

Edit `provision.ps1` for anything you want in every machine — it runs at first
logon with administrator rights, and the log lands in `C:\Windows\Temp\provision.log`.

`build-unattend-iso.sh` reads these from the environment:

| variable | default |
|---|---|
| `COMPUTER_NAME` | `win11` |
| `USERNAME` | `sandbox` |
| `PASSWORD` | prompted |
| `TIMEZONE` | `Eastern Standard Time` |
| `IMAGE_NAME` | `Windows 11 Pro` |
| `PRODUCT_KEY` | generic Win11 Pro KMS client key |
| `WINGET` | *(empty)* — space-separated package IDs |
| `ISO_STORAGE` | `local` |

## The answer-file ISO is a credential

Windows Setup needs the account password in a form it can read, so it is written
to the ISO in clear text. There is no way around this; base64 in an unattend file
is obfuscation, not encryption.

The scripts handle it as far as they can — the ISO is `chmod 600`, and
`make-template.sh` detaches it before converting the VM, so clones do not ship
with a readable password on a mounted CD. Delete it when you are done building:

```sh
rm /var/lib/vz/template/iso/unattend-*.iso
```

## Windows 11 24H2 / 25H2 notes

25H2 media runs the rewritten setup engine (it logs itself as `MOUPG`). Three
things behave differently, all found the hard way on the first build here:

**`PnpCustomizationsWinPE` is rejected.** The documented way to inject storage
drivers — `<DriverPaths>` with `<PathAndCredentials>` — makes the new engine abort
WinPE initialisation outright:

```
CSI  (F) E_INVALIDARG  from CWcmStateNodeCore::GetOrCreateChildOneLevel(
     node name = PathAndCredentials, ...)
MOUPG  CDlpActionWinpeInitialization::ExecuteRoutine(224): Result = 0x80070057
```

Setup then shows `0x80070057 - 0x40030` and, because the driver never loaded, no
disk. This directory instead calls `drvload` from `RunSynchronous`, which runs
early enough in the windowsPE pass that the controller is present before
`DiskConfiguration` looks for a disk. Same outcome, mechanism the engine accepts.

**A virtio-scsi install produces an unbootable system.** `drvload` gets Setup
past "no drives", but it loads the driver into the WinPE session only — nothing
puts it into the image being installed. Setup then completes happily and the
first boot from that disk bluescreens INACCESSIBLE_BOOT_DEVICE, because the
running OS has no driver for the controller it is booting from. The construct
that would normally persist it, `PathAndCredentials`, is the one this engine
rejects. Hence: install on AHCI, install the VirtIO package into the OS, then
`switch-to-virtio.sh`. Windows drives AHCI natively, so the install needs no
injected driver at all and that entire class of failure disappears.

**Installing the VirtIO MSI is not enough to boot from virtio-scsi.** The MSI
only stages the driver in the driver store. Windows binds a driver when it sees
matching hardware, and while the disk is on AHCI there is no virtio-scsi
controller to see -- so `vioscsi.sys` never reaches `C:\Windows\System32\drivers`
and its service is never registered `Start=0` (BOOT_START). Moving the boot disk
at that point bluescreens exactly as before. `switch-to-virtio.sh` handles this:
it attaches a throwaway virtio-scsi disk, waits for Windows to bind the driver,
checks the service key, and only then moves the real disk. Verify by hand with:

```
reg query HKLM\SYSTEM\CurrentControlSet\Services\vioscsi /v Start
```

**`<Order>` is scoped per list.** `CreatePartitions`, `ModifyPartitions` and
`RunSynchronous` each number from 1 independently. Continuing one sequence across
lists gets the whole `DiskConfiguration` rejected with `0x8007000D`
(`ERROR_INVALID_DATA`), and Setup silently drops to the interactive drive picker
rather than telling you which setting it disliked.

**Logs moved.** Setup writes to `X:\$WINDOWS.~BT\Sources\Panther\`, not the
classic `X:\Windows\Panther\`. `setuperr.log` there is where every diagnosis in
this file came from. Note `findstr` is absent from this WinPE, so use `type`.

`build-unattend-iso.sh` also strips comments from the rendered answer file and
rejects non-ASCII characters. The CSI parser reports every complaint as one
opaque code, so anything it does not need is worth not shipping.

## Debugging from outside the guest

`tools/` holds two scripts for when an install misbehaves and the guest has no
network yet. Both drive the Proxmox API, so they work from any machine that can
reach the cluster — no console session, no SSH to the node.

```sh
export PVE_TOKEN='sandboxctl@pve!ui=<secret>'

# See the screen. Speaks just enough RFB to pull one framebuffer as a PNG.
python tools/pvescreenshot.py PVE_HOST NODE 120 screen.png

# Type at it. Shift+F10 opens a command prompt during Setup.
python tools/pvekeys.py PVE_HOST NODE 120 --key shift-f10
python tools/pvekeys.py PVE_HOST NODE 120 \
    --text 'type X:$WINDOWS.~BT\Sources\Panther\setuperr.log' --enter
python tools/pvescreenshot.py PVE_HOST NODE 120 log.png
```

The same `sendkey` endpoint also clears the "Press any key to boot from CD"
prompt, so the one manual step is automatable after all:

```sh
for i in $(seq 16); do
  curl -sk -X PUT -H "Authorization: PVEAPIToken=root@pam!claude:$PVE_TOKEN"     -d key=ret "https://NODE:8006/api2/json/nodes/NODE/qemu/VMID/sendkey"
  sleep 0.7
done
```

Send these only across the boot window. Once the answer file is driving, stray
keypresses are the last thing Setup needs.

## Troubleshooting

| symptom | cause |
|---|---|
| `0x80070057 - 0x40030` | WinPE init failed. Almost always a construct the answer file parser rejected — read `setuperr.log`, see the 24H2/25H2 notes above. |
| *"We couldn't find any drives"* / no disk listed | The virtio driver did not load. Confirm with `wmic diskdrive get index,model,size` in a Shift+F10 shell; `drvload E:\vioscsi\w11\amd64\vioscsi.inf` should make it appear. |
| Setup shows the drive picker instead of installing | `DiskConfiguration` was rejected. `setuperr.log` names the file and the code; `0x8007000D` means invalid data in that section. |
| Setup stops on the edition picker | `IMAGE_NAME` does not match an edition in `install.wim`. |
| OOBE demands a Microsoft account | The answer file was not found. `setupact.log` logs the full path when it is. |
| No apps installed, everything else fine | winget was unavailable at first logon. Expected on fresh media; see the `[warn]` lines in `provision.log`. |
| Guest agent never answers | VirtIO install failed. Check `C:\Windows\Temp\provision.log`, then re-run `provision.ps1` from the mounted CD. |
| sysprep exits without shutting down | A per-user Store app blocks generalize. `C:\Windows\System32\Sysprep\Panther\setuperr.log` names it. |

## Backups

New VMs are **not** automatically in a backup job, and `provision/monit/pve-backup-check.py`
will alert on that within a day — that check exists precisely to catch a new
guest nobody added to a job. Either add the VM to a job, or, if it is disposable,
add its ID to `ALLOW_UNPROTECTED` in that script.

Templates themselves do not need backing up if these scripts are in git: the
template is reproducible from the ISO plus this directory.
