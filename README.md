## Triangle Check: scan iTunes backups for traces of compromise by Operation Triangulation

This script allows to scan iTunes backups for indicator of compromise by Operation Triangulation.

For more information, please read [Securelist](https://securelist.com/trng-2023/)

Contact: [triangulation@kaspersky.com](mailto:triangulation@kaspersky.com)

## Prerequisites

The script depends on: colorama (for pretty printing), pycryptodome

## Installation

The triangle_check utility can be installed from [PyPI](https://pypi.org/project/triangle-check/) (recommended):

```
python -m pip install triangle_check
```

The script can be run as-is (the subdirectory *triangle_check* is required):

```
python -m pip install -r requirements.txt
python triangle_check.py 
```

It can also be built into a pip package:

```
git clone https://github.com/KasperskyLab/triangle_check
cd triangle_check
python -m build
python -m pip install dist/triangle_check-1.0-py3-none-any.whl
```

For Windows or Linux, alternatively use the [binary builds](https://github.com/KasperskyLab/triangle_check/releases) of the triangle_check utility.  

## Usage

```
Usage: python -m triangle_check /path/to/iTunes_backup [backup_password]
```

### iTunes backup location

Locate the backup directory created by iTunes. The exact location depends on the OS and is described [here](https://support.apple.com/en-us/HT204215).
The directory you are looking for should contain may subdirectories, and should include 'Manifest.db', 'Manifest.plist'. The backup may be encrypted
with a password, if set up in iTunes. That password is required to decrypt password-protected backups.

### Advanced: create backup with libimobiledevice

You can use the tool *idevicebackup2* that is a part of the open-source package named [libimobiledevice](https://libimobiledevice.org/). Popular Linux 
distributions, macports and homebrew allow to install it out of the box, and the package can be built from the source code for Linux or OSX. 

### Scanning the backup

Run the tool against the backup directory. If there are any traces of suspicious activity, the script will print out *SUSPICION* or *DETECTED* lines with
more information and detected IOCs, and that would mean that the device was *most likely* compromised.

Example output:

```
==== IDENTIFIED TRACES OF COMPROMISE (Operation Triangulation) ====
2022-*-* SUSPICION Suspicious combination of events: 
 * file modification: Library/SMS/Attachments/ab/11
 * file attribute change: Library/SMS/Attachments/ab/11
 * location service stopped: com.apple.locationd.bundle-/System/Library/LocationBundles/WRMLinkSelection.bundle
 * file modification: Library/Preferences/com.apple.ImageIO.plist
 * file attribute change: Library/Preferences/com.apple.ImageIO.plist
 * file birth: Library/Preferences/com.apple.ImageIO.plist
 * file modification: Library/Preferences/com.apple.locationd.StatusBarIconManager.plist
 * file attribute change: Library/Preferences/com.apple.locationd.StatusBarIconManager.plist
 * file birth: Library/Preferences/com.apple.locationd.StatusBarIconManager.plist
2022-*-* DETECTED Exact match by NetUsage : BackupAgent
2022-*-* DETECTED Exact match by NetTimestamp : BackupAgent
```

## What's next?

The research on the Operation Triangulation is ongoing. For more updates, please check [Securelist](https://securelist.ru/trng-2023/)
