import hashlib, html, ipaddress, json, os, re, socket, sqlite3, threading, time
from datetime import datetime, timezone
from html.parser import HTMLParser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse
from urllib.request import Request, urlopen

ROOT=os.path.dirname(os.path.abspath(__file__))
DB=os.path.join(ROOT,"signalwatch.db")
HOST="127.0.0.1"; PORT=int(os.environ.get("PORT","8000"))
MIN_INTERVAL=900
LOCK=threading.RLock()

class Extractor(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True); self.skip=0; self.parts=[]
    def handle_starttag(self,tag,attrs):
        if tag in ("script","style","noscript","svg","canvas"): self.skip+=1
        if tag in ("p","div","li","h1","h2","h3","br","tr","section","article"): self.parts.append(" ")
    def handle_endtag(self,tag):
        if tag in ("script","style","noscript","svg","canvas") and self.skip: self.skip-=1
        if tag in ("p","div","li","h1","h2","h3","br","tr","section","article"): self.parts.append(" ")
    def handle_data(self,data):
        if not self.skip: self.parts.append(data)

def now(): return datetime.now(timezone.utc).isoformat(timespec="seconds")
def connect():
    c=sqlite3.connect(DB,timeout=10); c.row_factory=sqlite3.Row; c.execute("PRAGMA foreign_keys=ON"); return c
def init():
    with connect() as c:
        c.execute("""CREATE TABLE IF NOT EXISTS monitors(id INTEGER PRIMARY KEY,name TEXT NOT NULL,url TEXT UNIQUE NOT NULL,interval_minutes INTEGER NOT NULL,sensitivity TEXT NOT NULL,last_hash TEXT,last_checked TEXT,last_changed TEXT,status TEXT DEFAULT 'pending',message TEXT DEFAULT '')""")
        c.execute("""CREATE TABLE IF NOT EXISTS snapshots(id INTEGER PRIMARY KEY,monitor_id INTEGER REFERENCES monitors(id) ON DELETE CASCADE,checked_at TEXT,hash TEXT,text TEXT,title TEXT,status_code INTEGER)""")
        c.execute("""CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY,monitor_id INTEGER REFERENCES monitors(id) ON DELETE CASCADE,created_at TEXT,kind TEXT,message TEXT)""")
def event(c,mid,kind,msg): c.execute("INSERT INTO events(monitor_id,created_at,kind,message) VALUES(?,?,?,?)",(mid,now(),kind,msg))
def safe_url(url):
    p=urlparse(url.strip())
    if p.scheme not in ("http","https") or not p.hostname: raise ValueError("Enter a complete public http:// or https:// URL.")
    if p.username or p.password: raise ValueError("URLs containing credentials are not accepted.")
    try: ips=socket.getaddrinfo(p.hostname,p.port or (443 if p.scheme=="https" else 80),type=socket.SOCK_STREAM)
    except Exception: raise ValueError("Hostname could not be resolved.")
    for x in ips:
        if not ipaddress.ip_address(x[4][0]).is_global: raise ValueError("Only publicly routable websites are allowed.")
    return url.strip()
def fetch(url):
    url=safe_url(url)
    req=Request(url,headers={"User-Agent":"SignalWatch/0.1 (public page change monitor)","Accept":"text/html,text/plain,*/*"})
    with urlopen(req,timeout=15) as r: status=r.status; ctype=r.headers.get("Content-Type",""); raw=r.read(2000001)
    if "text" not in ctype and "html" not in ctype and "xml" not in ctype: raise ValueError("Response is not a text/HTML page.")
    m=re.search(r"charset=([\\w-]+)",ctype,re.I)
    try: source=raw[:2000000].decode(m.group(1) if m else "utf-8",errors="replace")
    except LookupError: source=raw.decode("utf-8",errors="replace")
    tm=re.search(r"<title[^>]*>(.*?)</title>",source,re.I|re.S)
    title=re.sub(r"\\s+"," ",html.unescape(re.sub(r"<[^>]+>"," ",tm.group(1)))).strip() if tm else ""
    ex=Extractor(); ex.feed(source); text=" ".join("".join(ex.parts).split())
    text=re.sub(r"\\b\\d{1,2}:\\d{2}(?::\\d{2})?\\s*(?:AM|PM)?\\b"," ",text,flags=re.I)
    text=re.sub(r"\\s+"," ",text).strip()
    if not text: raise ValueError("No readable text found; the site may require JavaScript.")
    return status,title,text
def check(mid):
    with LOCK:
        with connect() as c: row=c.execute("SELECT * FROM monitors WHERE id=?",(mid,)).fetchone()
        if not row:return
        try:
            status,title,text=fetch(row["url"])
            norm=text.lower() if row["sensitivity"]=="low" else text
            if row["sensitivity"]=="low": norm=re.sub(r"[\\W_]+"," ",norm)
            digest=hashlib.sha256(norm.encode()).hexdigest()
            with connect() as c:
                old=c.execute("SELECT last_hash FROM monitors WHERE id=?",(mid,)).fetchone()["last_hash"]
                changed=bool(old and old!=digest)
                if not old or changed:
                    c.execute("INSERT INTO snapshots(monitor_id,checked_at,hash,text,title,status_code) VALUES(?,?,?,?,?,?)",(mid,now(),digest,text,title,status))
                event(c,mid,"change" if changed else ("baseline" if not old else "check"),"Meaningful text change detected." if changed else ("Initial baseline saved." if not old else "No meaningful text change."))
                c.execute("UPDATE monitors SET last_hash=?,last_checked=?,last_changed=CASE WHEN ? THEN ? ELSE last_changed END,status='ok',message=? WHERE id=?",(digest,now(),int(changed),now(),"Change detected" if changed else "No meaningful text change",mid))
        except Exception as e:
            with connect() as c:
                c.execute("UPDATE monitors SET last_checked=?,status='error',message=? WHERE id=?",(now(),str(e)[:220],mid)); event(c,mid,"error",str(e)[:220])
def scheduler():
    while True:
        try:
            with connect() as c: rows=c.execute("SELECT id,last_checked,interval_minutes FROM monitors").fetchall()
            for r in rows:
                due=not r["last_checked"]
                if r["last_checked"]:
                    try: due=time.time()-datetime.fromisoformat(r["last_checked"]).timestamp()>=max(MIN_INTERVAL,r["interval_minutes"]*60)
                    except Exception: due=True
                if due: threading.Thread(target=check,args=(r["id"],),daemon=True).start()
        except Exception as e: print("Scheduler:",e)
        time.sleep(20)
class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def sendj(self,data,code=200):
        b=json.dumps(data).encode(); self.send_response(code); self.send_header("Content-Type","application/json; charset=utf-8"); self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b)
    def readj(self):
        n=int(self.headers.get("Content-Length","0"))
        if n>50000: raise ValueError("Request too large.")
        return json.loads(self.rfile.read(n) or b"{}")
    def do_GET(self):
        p=urlparse(self.path).path
        if p=="/":
            b=open(os.path.join(ROOT,"index.html"),"rb").read(); self.send_response(200); self.send_header("Content-Type","text/html; charset=utf-8"); self.send_header("Content-Length",str(len(b))); self.end_headers(); self.wfile.write(b); return
        with connect() as c:
            if p=="/api/monitors": data=[dict(x) for x in c.execute("SELECT * FROM monitors ORDER BY id DESC")]
            elif p=="/api/events": data=[dict(x) for x in c.execute("SELECT events.*,monitors.name AS monitor_name FROM events JOIN monitors ON monitors.id=events.monitor_id ORDER BY events.id DESC LIMIT 50")]
            elif p.startswith("/api/history/"):
                try: mid=int(p.rsplit("/",1)[1])
                except: return self.sendj({"error":"Invalid id"},400)
                data=[dict(x) for x in c.execute("SELECT checked_at,title,text,status_code FROM snapshots WHERE monitor_id=? ORDER BY id DESC LIMIT 20",(mid,))]
            else: return self.sendj({"error":"Not found"},404)
        self.sendj(data)
    def do_POST(self):
        p=urlparse(self.path).path
        try: d=self.readj()
        except Exception as e: return self.sendj({"error":str(e)},400)
        if p=="/api/monitors":
            name=str(d.get("name","")).strip()[:100]; url=str(d.get("url","")).strip()
            try:
                interval=int(d.get("interval_minutes",60))
                if not name or not url: raise ValueError("Name and URL are required.")
                if not 15<=interval<=1440: raise ValueError("Interval must be between 15 minutes and 24 hours.")
                url=safe_url(url)
            except Exception as e: return self.sendj({"error":str(e)},400)
            sensitivity=d.get("sensitivity","normal")
            if sensitivity not in ("low","normal","high"): sensitivity="normal"
            try:
                with connect() as c:
                    cur=c.execute("INSERT INTO monitors(name,url,interval_minutes,sensitivity) VALUES(?,?,?,?)",(name,url,interval,sensitivity)); mid=cur.lastrowid; event(c,mid,"created","Monitor added.")
                threading.Thread(target=check,args=(mid,),daemon=True).start()
                return self.sendj({"id":mid,"message":"Monitor added; baseline check started."},201)
            except sqlite3.IntegrityError: return self.sendj({"error":"That URL is already monitored."},409)
        if p.startswith("/api/check/"):
            try: mid=int(p.rsplit("/",1)[1])
            except: return self.sendj({"error":"Invalid id"},400)
            threading.Thread(target=check,args=(mid,),daemon=True).start(); return self.sendj({"message":"Check started."},202)
        if p.startswith("/api/delete/"):
            try: mid=int(p.rsplit("/",1)[1])
            except: return self.sendj({"error":"Invalid id"},400)
            with connect() as c: c.execute("DELETE FROM monitors WHERE id=?",(mid,))
            return self.sendj({"message":"Deleted"})
        return self.sendj({"error":"Not found"},404)
if __name__=="__main__":
    init(); threading.Thread(target=scheduler,daemon=True).start()
    print("SignalWatch running at http://127.0.0.1:%s"%PORT)
    ThreadingHTTPServer((HOST,PORT),Handler).serve_forever()
