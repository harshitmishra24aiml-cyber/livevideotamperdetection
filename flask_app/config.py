import os
from pathlib import Path
ROOT=Path(__file__).resolve().parent
DATA=Path(os.environ.get('SENTINEL_DATA_DIR',ROOT/'data')); UPLOADS=DATA/'uploads'; EVIDENCE=DATA/'evidence'; DB=DATA/'sentinel.sqlite3'
for p in (DATA,UPLOADS,EVIDENCE): p.mkdir(parents=True,exist_ok=True)
