from colorama import Fore, Style
import colorama
import sys
import getpass
from . import IOSBackupChecker
from datetime import datetime
from datetime import timezone

def ask_password():
    return getpass.getpass('The backup is encrypted, please enter the password:').encode('utf-8')

def main():
    colorama.init()

    dir = '.'
    password = None
    if len(sys.argv) == 1:
        print('Triangle Check: scan iTunes backups for traces of compromise by Operation Triangulation © 2023 AO Kaspersky Lab. All Rights Reserved.')
        print('\n  Contact: triangulation@kaspersky.com')
        print('  More info: https://securelist.ru/trng-2023/')
        print('\nUsage: python -m triangle_check /path/to/iTunes_backup [backup_password]')
        return
    if len(sys.argv) > 1:
        dir = sys.argv[1]
    if len(sys.argv) > 2:
        password = sys.argv[2].encode('utf-8')

    checker = IOSBackupChecker()
    try:
        results = checker.scan_dir(dir, password, ask_password)
    except RuntimeError as scan_fail:
        print(scan_fail)
        return

    if len(results) > 0:
        print(Fore.LIGHTRED_EX + '==== IDENTIFIED TRACES OF COMPROMISE (Operation Triangulation) ====' + Fore.RESET)
            
        for k in sorted(results): # k is a UNIX timestamp of detection
            for detection in results[k]:
                dt = datetime.fromtimestamp(k, tz=timezone.utc)
                explanation = checker.detection_to_string(detection)
                if detection[0] == 'exact':
                    print(f'{dt} ' + Fore.LIGHTRED_EX + 'DETECTED' + Fore.RESET + ' ' + explanation)
                elif detection[0] == 'heuristics':
                    print(f'{dt} ' + Fore.LIGHTYELLOW_EX + 'SUSPICION' + Fore.RESET + ' ' + explanation)
        sys.exit(2)
    else:
        print(Fore.GREEN + 'No traces of compromise were identified' + Fore.RESET)
        sys.exit(0)


if __name__ == "__main__":
    main()
