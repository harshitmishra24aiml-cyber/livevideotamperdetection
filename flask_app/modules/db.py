import sqlite3
from config import DB
def conn():
 c=sqlite3.connect(DB); c.row_factory=sqlite3.Row; return c
def init():
 with conn() as c:
  c.executescript("""PRAGMA foreign_keys=ON;
  CREATE TABLE IF NOT EXISTS cameras(id TEXT PRIMARY KEY,name TEXT,public_key TEXT,active INTEGER DEFAULT 1);
  CREATE TABLE IF NOT EXISTS sessions(id TEXT PRIMARY KEY,source TEXT,frames INTEGER,root TEXT,created TEXT DEFAULT CURRENT_TIMESTAMP);
  CREATE TABLE IF NOT EXISTS frame_records(session TEXT,seq INTEGER,ts REAL,hash TEXT,chain TEXT,scene TEXT,PRIMARY KEY(session,seq));
  CREATE TABLE IF NOT EXISTS alerts(id INTEGER PRIMARY KEY,session TEXT,kind TEXT,severity TEXT,message TEXT);
  CREATE TABLE IF NOT EXISTS sensor_events(id INTEGER PRIMARY KEY,session TEXT,sensor TEXT,value TEXT,ts REAL);
  CREATE TABLE IF NOT EXISTS simulations(id INTEGER PRIMARY KEY,session TEXT,attack TEXT,detected INTEGER,detail TEXT);""")
def query(sql,args=()):
 with conn() as c: return [dict(x) for x in c.execute(sql,args).fetchall()]
