#!/bin/bash

if [ $# -ne 1 -o ! -d "$1" ]; then
  echo "usage: $0 PATH_TO_BACKUP_DIR"
  exit 1
fi

python3 -m venv venv
. venv/bin/activate
pip3 install -r requirements.txt
python3 -m triangle_check $1
