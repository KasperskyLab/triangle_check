#!/usr/bin/env python3 
# © 2023 AO Kaspersky Lab. All Rights Reserved.
# Checks iTunes backups for traces of compromise by Operation Triangulation

import sqlite3
import plistlib
import tempfile
import hashlib
import struct
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import os.path
from datetime import timezone

cocoa_delta = 978307200.0 # 2001 - 1970, for adjusting to UNIX timestamps

def AESUnwrap(K, encrypted):
    C = []
    for i in range(len(encrypted)//8):
        C.append(struct.unpack(">Q", encrypted[i*8:i*8+8])[0])
    n = len(C) - 1

    #   1) Initialize variables.
    R = [0]
    A = C[0]

    for c in C[1:]:
        R.append(c)
    #    2) Compute intermediate values.
    for j in range(5, -1, -1):
        for i in range(n, 0, -1):
            buf = struct.pack(">2Q", A ^ (n*j+i), R[i])
            B = AES.new(K, AES.MODE_ECB).decrypt(buf)
            A, R[i] = struct.unpack(">2Q", B)

    #        A[0] = IV = A6A6A6A6A6A6A6A6
    if A != 0xa6a6a6a6a6a6a6a6:
        raise RuntimeError(f'Decrypt match fail, please check if the password is correct')
    
    #   3) Output results.
    P = b""
    for r in R[1:]:
        P += struct.pack(">Q", r)

    return P

class IOSBackupChecker:
    def __init__(self):
        self.temp_files = []

    def __del__(self):
        for fname in self.temp_files:
            os.unlink(fname)
        self.temp_files = []

    def decrypt_with_key(self, fname, key):
        iv=b"\x00" * 16
        with open(fname, 'rb') as f:
            handle, out_fname = tempfile.mkstemp()
            outf = os.fdopen(handle, 'wb')
            outf.write(unpad(AES.new(key, AES.MODE_CBC, iv).decrypt(f.read()), AES.block_size))
            outf.close()
        self.temp_files.append(out_fname)
        return out_fname

    def decrypt_with_manifest(self, path, domain):
        cur = self.fsdb.cursor()
        cur.execute(f"SELECT fileID, file  FROM Files WHERE relativePath = '{path}' AND domain = '{domain}'")
        fileID, plist = cur.fetchone()
        fs_info = plistlib.loads(plist)
        fs_objects = fs_info['$objects']
        fs_stat = fs_objects[1]
        path = os.path.join(self.dir, fileID[0:2], fileID)
        if self.encrypted:
            key = AESUnwrap(self.class_keys[int(fs_stat['ProtectionClass'])]['key'], fs_objects[fs_stat['EncryptionKey'].data]['NS.data'][4:])
            path = self.decrypt_with_key(path, key)
        return path

    def append_map(self, timestamp, item, map):
        if not timestamp in map:
            map[timestamp] = []
        map[timestamp].append(item)

    def append_timeline(self,timestamp, item):
        self.append_map(timestamp, item, self.timeline)

    def append_detection(self,timestamp, item):
        self.append_map(timestamp, item, self.detections)

    def run_heuristics(self, event_window):
        sms_attachment_directories = {}
        timestamp_start = event_window[0][0]

        event_classes = set()

        for (event_timestamp, event) in event_window:
            event_type = event[0]
            if event_type in ['M', 'C', 'B']: # filesystem events
                path = event[1]
                if path.startswith('Library/SMS/Attachments/'):
                    #Library/SMS/Attachments/00/00 - good
                    #Library/SMS/Attachments/00 - also good
                    ##Library/SMS/Attachments/00/00/something else - legitimate attachment, bail out
                    num_slashes = path.count('/')
                    if num_slashes == 3 or num_slashes == 4:
                        sms_attachment_directories[path] = sms_attachment_directories.get(path, {})
                        sms_attachment_directories[path][event_type] = True
                    else:
                        return # False positive!
                else: # suspicious locations
                    event_classes.add('file')
            elif event_type in ['NetTimestamp', 'NetUsage', 'NetFirst', 'NetTimestamp2']:
                event_classes.add('net')
            elif event_type == 'LocationTimeStopped':
                event_classes.add('location')

        # Now, for each directory, check that both have 'M' and 'C'
        for k, v in sms_attachment_directories.items():
            if (not 'M' in v) or (not 'C' in v):
                return False
            
        if (len(sms_attachment_directories) > 0):
            event_classes.add('sms')

        detection_threshold = 2

        if len(event_classes) >= detection_threshold:
            self.append_detection(timestamp_start, ('heuristics', event_window))

    def scan_dir(self, backup_dir, backup_password, ask_password_func):
        self.dir = backup_dir
        
        with open(os.path.join(self.dir, 'Manifest.plist'), 'rb') as f:
            self.plist = plistlib.load(f)
        self.encrypted = self.plist['IsEncrypted']

        temp_files = []
        manifest_db_path = os.path.join(self.dir, "Manifest.db")
        with open(manifest_db_path, 'rb') as f:
            if f.read(4) == b'SQLi':
                self.encrypted = False # Already decrypted

        if self.encrypted and (backup_password is None):
            backup_password = ask_password_func()

        self.timeline = {}
        self.detections = {}

        if self.encrypted:
            key_bag = self.plist['BackupKeyBag']

            keys = {}
            offset = 0
            ctx = None
            self.class_keys = {}
            while offset + 8 <= len(key_bag) :
                block_id = key_bag[offset:offset+4]
                block_len = struct.unpack(">L", key_bag[offset+4:offset+8])[0]
                #print(f'{block_id} {block_len} {key_bag[offset+8:offset+8+block_len]}')
                key_data = key_bag[offset+8:offset+8+block_len]
                keys[block_id] = key_data
                if block_id == b'UUID':
                    ctx = {}
                elif block_id == b'CLAS':
                    ctx['class'] = struct.unpack(">L", key_data)[0]
                elif block_id == b'WRAP':
                    ctx['wrap'] = struct.unpack(">L", key_data)[0]
                elif block_id == b'WPKY':
                    ctx['key'] = key_data
                    if ctx['class'] in self.class_keys:
                        raise RuntimeError(f'Duplicate class key {ctx["class"]}')
                    self.class_keys[ctx['class']] = ctx
                    ctx = {}
                offset += 8 + block_len

            product_ver = self.plist['Lockdown']['ProductVersion'].split('.')
            major, minor = int(product_ver[0]), int(product_ver[1])

            material = backup_password
            if major > 10 or (major == 10 and minor > 2):
                material = hashlib.pbkdf2_hmac('sha256', backup_password, keys[b'DPSL'], struct.unpack(">L", keys[b'DPIC'])[0], 32)
            key = hashlib.pbkdf2_hmac('sha1', material, keys[b'SALT'], struct.unpack(">L", keys[b'ITER'])[0], 32)

            for k, v in self.class_keys.items():
                v['key'] = AESUnwrap(key, v['key'])
                self.class_keys[k] = v

            manifest_key = self.plist['ManifestKey']
            manifest_key_class = struct.unpack("<L", manifest_key[0:4])[0]
            manifest_key = manifest_key[4:]
            manifest_key = AESUnwrap(self.class_keys[manifest_key_class]['key'], manifest_key)
            manifest_db_path = self.decrypt_with_key(manifest_db_path, manifest_key)
        
        self.fsdb = sqlite3.connect(manifest_db_path)

        cur = self.fsdb.cursor()
        for fileID, domain, relativePath, flags, file in cur.execute("SELECT fileID, domain, relativePath, flags, file FROM Files WHERE (relativePath LIKE 'Library/SMS/Attachments/%' AND domain = 'MediaDomain') "
                                                                     "OR ( relativePath = 'Library/Preferences/com.apple.ImageIO.plist' AND domain = 'RootDomain' ) "
                                                                     "OR ( relativePath = 'Library/Preferences/com.apple.locationd.StatusBarIconManager.plist' AND domain = 'HomeDomain' ) "
                                                                     "OR ( relativePath = 'Library/Preferences/com.apple.imservice.ids.FaceTime.plist' AND domain = 'HomeDomain') "):
            # "2022-06-22 --:--:--.000000","Manifest","M-CB","Library/Preferences/com.apple.ImageIO.plist - RootDomain"
            fs_info = plistlib.loads(file)
            fs_stat = fs_info['$objects'][1]
            self.append_timeline(fs_stat['LastModified'], ('M', relativePath))
            self.append_timeline(fs_stat['LastStatusChange'], ('C', relativePath))
            self.append_timeline(fs_stat['Birth'], ('B', relativePath))

        path_osanalytics = self.decrypt_with_manifest('Library/Preferences/com.apple.osanalytics.addaily.plist', 'HomeDomain')
        path_datausage = self.decrypt_with_manifest('Library/Databases/DataUsage.sqlite', 'WirelessDomain')

        process_IOCs_exact = ['BackupAgent']
        process_IOCs_implicit = ['nehelper', 'com.apple.WebKit.WebContent', 'powerd/com.apple.datausage.diagnostics', 'lockdownd/com.apple.datausage.security']

        with open(path_osanalytics, 'rb') as f:
            osanalytics = plistlib.load(f)
        baseline = osanalytics['netUsageBaseline']
        for package in baseline:
            if package in process_IOCs_exact:
                self.append_detection(baseline[package][0].replace(tzinfo=timezone.utc).timestamp(), ('exact', 'NetUsage', package))
            if (package in process_IOCs_implicit) or (package in process_IOCs_exact):
                self.append_timeline(baseline[package][0].replace(tzinfo=timezone.utc).timestamp(), ('NetUsage', package))

        datausage = sqlite3.connect(path_datausage)
        data_cur = datausage.cursor()
        for first_timestamp, proc_timestamp, procname, bundlename, pk, timestamp in data_cur.execute('SELECT ZPROCESS.ZFIRSTTIMESTAMP,ZPROCESS.ZTIMESTAMP,ZPROCESS.ZPROCNAME,ZPROCESS.ZBUNDLENAME,ZPROCESS.Z_PK,'
                         'ZLIVEUSAGE.ZTIMESTAMP FROM ZLIVEUSAGE LEFT JOIN ZPROCESS ON ZLIVEUSAGE.ZHASPROCESS = ZPROCESS.Z_PK UNION '
                        'SELECT ZFIRSTTIMESTAMP, ZTIMESTAMP, ZPROCNAME, ZBUNDLENAME, Z_PK, NULL FROM ZPROCESS WHERE Z_PK NOT IN (SELECT ZHASPROCESS FROM ZLIVEUSAGE)'):
            if procname in process_IOCs_exact:
                self.append_detection(cocoa_delta + first_timestamp, ('exact', 'NetFirst', procname))
                self.append_detection(cocoa_delta + proc_timestamp, ('exact', 'NetTimestamp', procname))
                if timestamp is not None:
                    self.append_detection(cocoa_delta + timestamp, ('exact', 'NetTimestamp2', procname))
            elif (procname in process_IOCs_exact) or (procname in process_IOCs_implicit):
                self.append_timeline(cocoa_delta + first_timestamp, ('NetFirst', procname))
                self.append_timeline(cocoa_delta + proc_timestamp, ('NetTimestamp', procname))
                if timestamp is not None:
                    self.append_timeline(cocoa_delta + timestamp, ('NetTimestamp2', procname))

        # "2022-09-12 17:06:21.659304","LocationdClients","LocationTimeStopped","LocationTimeStopped from com.apple.locationd.bundle-/System/Library/LocationBundles/IonosphereHarvest.bundle"
        datausage.close()

        location_client_IOCs = ['com.apple.locationd.bundle-/System/Library/LocationBundles/IonosphereHarvest.bundle', 'com.apple.locationd.bundle-/System/Library/LocationBundles/WRMLinkSelection.bundle']

        path_locationd_clients = self.decrypt_with_manifest('Library/Caches/locationd/clients.plist', 'RootDomain')
        with open(path_locationd_clients, 'rb') as f:
            locationd_clients = plistlib.load(f)
            for package in locationd_clients:
                #if package in :
                #print(f'{package} {locationd_clients[package]}')
                item = locationd_clients[package]
                if (package in location_client_IOCs) and ('LocationTimeStopped' in item):
                    self.append_timeline(cocoa_delta + item['LocationTimeStopped'], ('LocationTimeStopped', package))

        self.fsdb.close()

        # There goes the heuristics part
        expanded_timeline = []
        for k in sorted(self.timeline):
            for item in self.timeline[k]:
                expanded_timeline.append((k, item))

        # Make a sliding window of 1 minute and max 10 events, check for specific events
        events_max = 10
        time_delta_max = 60*5 # 5 minutes window
        for i in range(len(expanded_timeline)-events_max):
            timestamp_start = expanded_timeline[i][0]
            event_window = expanded_timeline[i:i+events_max]
            for j in range(len(event_window)):
                timestamp_item = event_window[j][0]
                if timestamp_item - timestamp_start > time_delta_max:
                    event_window = event_window[:j]
                    break

            self.run_heuristics(event_window)

        return self.detections
    
    def detection_to_string(self, detection):
        if detection[0] == 'exact':
            return f'Exact match by {detection[1]} : {detection[2]}'
        elif detection[0] == 'heuristics':
            str = f'Suspicious combination of events: '
            for timestamp, event in detection[1]:
                event_type = event[0]
                if event_type == 'M':
                    str += f'\n * file modification: {event[1]}'
                elif event_type == 'C':
                    str += f'\n * file attribute change: {event[1]}'
                elif event_type == 'B':
                    str += f'\n * file birth: {event[1]}'
                elif event_type == 'LocationTimeStopped':
                    str += f'\n * location service stopped: {event[1]}'
                elif event_type in ['NetTimestamp', 'NetUsage', 'NetFirst', 'NetTimestamp2']:
                    str += f'\n * traffic by process {event[1]}'
                else:
                    raise RuntimeError(f'Unknown detection event {event_type}')
            return str
 
