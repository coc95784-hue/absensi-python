from flask import Flask, render_template_string, request, jsonify, session, redirect, url_for, send_file, send_from_directory
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import sqlite3, secrets, re, io, csv, os, base64
from datetime import datetime, date

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "ganti-ini-random-panjang-12345")

DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "absensi.db")
KODE_GURU_DEFAULT = "GURU2025"
DAFTAR_KELAS = ["7A","7B","7C","8A","8B","8C","9A","9B","9C"]

# ============================================================
# DATABASE
# ============================================================
def get_db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    conn = sqlite3.connect(DB_PATH)
    c = conn.cursor()
    c.execute("""CREATE TABLE IF NOT EXISTS sekolah (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        nama TEXT NOT NULL,
        kode TEXT UNIQUE NOT NULL,
        jam_batas_masuk TEXT DEFAULT '07:15',
        jam_pulang_mulai TEXT DEFAULT '13:00',
        kode_guru TEXT DEFAULT 'GURU2025',
        created_at TEXT NOT NULL
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        nama TEXT NOT NULL,
        email TEXT,
        no_wa TEXT,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'siswa',
        sekolah_id INTEGER NOT NULL,
        kelas TEXT,
        qr_token TEXT UNIQUE,
        created_at TEXT NOT NULL
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS absensi (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        tanggal TEXT NOT NULL,
        jam_masuk TEXT,
        jam_pulang TEXT,
        status TEXT NOT NULL,
        terlambat INTEGER DEFAULT 0,
        via_izin INTEGER DEFAULT 0,
        UNIQUE(user_id, tanggal)
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS hari_libur (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sekolah_id INTEGER NOT NULL,
        tanggal TEXT NOT NULL,
        keterangan TEXT,
        UNIQUE(sekolah_id, tanggal)
    )""")
    c.execute("""CREATE TABLE IF NOT EXISTS pengajuan_izin (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        sekolah_id INTEGER NOT NULL,
        jenis TEXT NOT NULL,
        keterangan TEXT,
        foto TEXT NOT NULL,
        tanggal TEXT NOT NULL,
        status TEXT DEFAULT 'pending',
        created_at TEXT NOT NULL,
        reviewed_by INTEGER,
        reviewed_at TEXT,
        review_note TEXT
    )""")
    conn.commit()
    conn.close()

def today(): return date.today().isoformat()
def now_jam(): return datetime.now().strftime("%H:%M:%S")
def jam_short(): return datetime.now().strftime("%H:%M")

def cek_hari_libur(conn, sekolah_id, tgl):
    r = conn.execute("SELECT * FROM hari_libur WHERE sekolah_id=? AND tanggal=?", (sekolah_id, tgl)).fetchone()
    return dict(r) if r else None

def hitung_terlambat(batas, jam_masuk):
    try:
        bh, bm = map(int, batas.split(":"))
        jh, jm = map(int, jam_masuk.split(":"))
        return max(0, (jh*60+jm) - (bh*60+bm))
    except: return 0

# ============================================================
# AUTH HELPERS
# ============================================================
def login_required(f):
    @wraps(f)
    def w(*a, **kw):
        if "user_id" not in session:
            return jsonify({"ok": False, "msg": "Harus login", "redirect": "/"}), 401
        return f(*a, **kw)
    return w

def guru_required(f):
    @wraps(f)
    def w(*a, **kw):
        if session.get("role") not in ["admin", "guru"]:
            return jsonify({"ok": False, "msg": "Akses guru/admin only"}), 403
        return f(*a, **kw)
    return w

def admin_required(f):
    @wraps(f)
    def w(*a, **kw):
        if session.get("role") != "admin":
            return jsonify({"ok": False, "msg": "Akses admin only"}), 403
        return f(*a, **kw)
    return w

def gen_token(): return "S-" + secrets.token_hex(6).upper()
def gen_kode_sekolah(conn):
    while True:
        k = "SEK" + secrets.token_hex(2).upper()
        if not conn.execute("SELECT 1 FROM sekolah WHERE kode=?", (k,)).fetchone():
            return k

# ============================================================
# ROUTES
# ============================================================
@app.route("/")
def index():
    with open(os.path.join(os.path.dirname(__file__), "templates", "index.html"), encoding="utf-8") as f:
        return render_template_string(f.read())

@app.route("/api/login", methods=["POST"])
def api_login():
    d = request.get_json() or {}
    u = (d.get("username") or "").strip().lower()
    p = d.get("password") or ""
    if not u or not p:
        return jsonify({"ok": False, "msg": "Isi username & password"}), 400
    conn = get_db()
    row = conn.execute("SELECT * FROM users WHERE LOWER(username)=? OR LOWER(email)=?", (u, u)).fetchone()
    conn.close()
    if row and check_password_hash(row["password"], p):
        session["user_id"] = row["id"]
        session["role"] = row["role"]
        session["nama"] = row["nama"]
        return jsonify({"ok": True, "msg": f"Selamat datang, {row['nama']}", "role": row["role"]})
    return jsonify({"ok": False, "msg": "Username/password salah"}), 401

@app.route("/api/logout", methods=["POST"])
def api_logout():
    session.clear()
    return jsonify({"ok": True})

@app.route("/api/register", methods=["POST"])
def api_register():
    d = request.get_json() or {}
    mode = d.get("mode") or "join"
    kode_sek = (d.get("kode_sekolah") or "").strip().upper()
    nama_sek = (d.get("nama_sekolah") or "").strip()
    username = (d.get("username") or "").strip()
    nama = (d.get("nama") or "").strip()
    kelas = (d.get("kelas") or "").strip().upper()
    email = (d.get("email") or "").strip().lower()
    no_wa = (d.get("no_wa") or "").strip()
    password = d.get("password") or ""
    role = d.get("role") or "siswa"
    kode_guru = (d.get("kode_guru") or "").strip()

    if not username or not nama or not email or not password or not no_wa:
        return jsonify({"ok": False, "msg": "Semua field wajib diisi!"}), 400
    if len(password) < 6:
        return jsonify({"ok": False, "msg": "Password minimal 6 karakter"}), 400
    if mode == "join" and not kode_sek:
        return jsonify({"ok": False, "msg": "Kode sekolah wajib diisi"}), 400
    if mode == "create" and not nama_sek:
        return jsonify({"ok": False, "msg": "Nama sekolah wajib diisi"}), 400
    if role == "siswa" and not kelas:
        return jsonify({"ok": False, "msg": "Kelas wajib dipilih"}), 400
    if role == "siswa" and kelas not in DAFTAR_KELAS:
        return jsonify({"ok": False, "msg": "Kelas tidak valid"}), 400

    conn = get_db()
    if conn.execute("SELECT 1 FROM users WHERE LOWER(username)=?", (username.lower(),)).fetchone():
        conn.close(); return jsonify({"ok": False, "msg": "Username sudah dipakai"}), 400
    if conn.execute("SELECT 1 FROM users WHERE LOWER(email)=?", (email,)).fetchone():
        conn.close(); return jsonify({"ok": False, "msg": "Email sudah terdaftar"}), 400

    if mode == "join":
        s = conn.execute("SELECT * FROM sekolah WHERE kode=?", (kode_sek,)).fetchone()
        if not s:
            conn.close(); return jsonify({"ok": False, "msg": "Kode sekolah tidak ditemukan"}), 400
        sekolah_id = s["id"]
        if role == "guru" and kode_guru != s["kode_guru"]:
            conn.close(); return jsonify({"ok": False, "msg": "Kode guru salah"}), 400
    else:
        kode_baru = gen_kode_sekolah(conn)
        cur = conn.execute("INSERT INTO sekolah (nama, kode, created_at) VALUES (?,?,?)",
                           (nama_sek, kode_baru, datetime.now().isoformat()))
        sekolah_id = cur.lastrowid
        role = "admin"

    qr = gen_token() if role == "siswa" else None
    try:
        conn.execute("""INSERT INTO users (username,nama,email,no_wa,password,role,sekolah_id,kelas,qr_token,created_at)
                        VALUES (?,?,?,?,?,?,?,?,?,?)""",
                     (username, nama, email, no_wa, generate_password_hash(password), role,
                      sekolah_id, kelas if role == "siswa" else None, qr, datetime.now().isoformat()))
        conn.commit()
        msg = "Registrasi berhasil!"
        if mode == "create": msg += f" Kode sekolah: {kode_baru}"
        else: msg += " Silakan login."
        conn.close()
        return jsonify({"ok": True, "msg": msg})
    except sqlite3.IntegrityError as e:
        conn.close()
        return jsonify({"ok": False, "msg": "Data sudah terdaftar"}), 400

@app.route("/api/me")
@login_required
def api_me():
    conn = get_db()
    u = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    s = conn.execute("SELECT * FROM sekolah WHERE id=?", (u["sekolah_id"],)).fetchone()
    conn.close()
    return jsonify({"ok": True, "user": dict(u), "sekolah": dict(s)})

# ============================================================
# API: STATISTIK HARI INI
# ============================================================
@app.route("/api/dashboard")
@login_required
def api_dashboard():
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    sid = user["sekolah_id"]
    tgl = today()
    siswa = conn.execute("SELECT * FROM users WHERE sekolah_id=? AND role='siswa'", (sid,)).fetchall()
    absen = conn.execute("""SELECT a.*, u.nama as nama_siswa, u.kelas as kelas_siswa
                            FROM absensi a JOIN users u ON u.id=a.user_id
                            WHERE u.sekolah_id=? AND a.tanggal=?""", (sid, tgl)).fetchall()
    libur = cek_hari_libur(conn, sid, tgl)
    conn.close()
    data = [dict(a) for a in absen]
    hadir = sum(1 for a in data if a["status"] in ("Hadir","Terlambat"))
    izin = sum(1 for a in data if a["status"] == "Izin")
    sakit = sum(1 for a in data if a["status"] == "Sakit")
    terlambat = sum(1 for a in data if a["terlambat"])
    return jsonify({"ok": True,
        "stat": {"total": len(siswa), "hadir": hadir, "izin": izin, "sakit": sakit,
                 "belum": len(siswa) - len(data), "terlambat": terlambat},
        "absen_hari_ini": data, "hari_libur": libur})

# ============================================================
# API: DATA SISWA
# ============================================================
@app.route("/api/siswa", methods=["GET"])
@login_required
@guru_required
def api_siswa_list():
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    siswa = conn.execute("SELECT id,username,nama,kelas,qr_token,email,no_wa FROM users WHERE sekolah_id=? AND role='siswa' ORDER BY kelas, nama",
                        (user["sekolah_id"],)).fetchall()
    conn.close()
    return jsonify({"ok": True, "data": [dict(s) for s in siswa]})

@app.route("/api/siswa", methods=["POST"])
@login_required
@guru_required
def api_siswa_add():
    d = request.get_json() or {}
    nama = (d.get("nama") or "").strip()
    username = (d.get("username") or "").strip()
    kelas = (d.get("kelas") or "").strip().upper()
    password = d.get("password") or ""
    if not nama or not username or not kelas or len(password) < 6:
        return jsonify({"ok": False, "msg": "Lengkapi (password min 6)"}), 400
    if kelas not in DAFTAR_KELAS:
        return jsonify({"ok": False, "msg": "Kelas tidak valid"}), 400
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    if conn.execute("SELECT 1 FROM users WHERE LOWER(username)=?", (username.lower(),)).fetchone():
        conn.close(); return jsonify({"ok": False, "msg": "Username sudah dipakai"}), 400
    qr = gen_token()
    try:
        conn.execute("""INSERT INTO users (username,nama,password,role,sekolah_id,kelas,qr_token,created_at,email,no_wa)
                        VALUES (?,?,?,?,?,?,?,?,?,?)""",
                     (username, nama, generate_password_hash(password), "siswa",
                      user["sekolah_id"], kelas, qr, datetime.now().isoformat(), "", ""))
        conn.commit()
        conn.close()
        return jsonify({"ok": True, "msg": f"{nama} ditambah", "qr_token": qr})
    except sqlite3.IntegrityError:
        conn.close(); return jsonify({"ok": False, "msg": "Gagal simpan"}), 400

@app.route("/api/siswa/<int:uid>", methods=["DELETE"])
@login_required
@admin_required
def api_siswa_hapus(uid):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    target = conn.execute("SELECT * FROM users WHERE id=? AND sekolah_id=?", (uid, user["sekolah_id"])).fetchone()
    if not target:
        conn.close(); return jsonify({"ok": False, "msg": "User tidak ditemukan"}), 404
    conn.execute("DELETE FROM absensi WHERE user_id=?", (uid,))
    conn.execute("DELETE FROM pengajuan_izin WHERE user_id=?", (uid,))
    conn.execute("DELETE FROM users WHERE id=?", (uid,))
    conn.commit(); conn.close()
    return jsonify({"ok": True, "msg": "Dihapus"})

@app.route("/api/import-csv", methods=["POST"])
@login_required
@guru_required
def api_import_csv():
    d = request.get_json() or {}
    csv_text = d.get("csv") or ""
    if not csv_text.strip():
        return jsonify({"ok": False, "msg": "CSV kosong"}), 400
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    lines = [l for l in csv_text.replace("\r","").split("\n") if l.strip()]
    if len(lines) < 2:
        conn.close(); return jsonify({"ok": False, "msg": "CSV minimal 2 baris"}), 400
    def parse_line(line):
        out, cur, q = [], "", False
        for ch in line:
            if ch == '"':
                if q and cur.endswith('"'): cur += '"'
                else: q = not q
            elif ch == ',' and not q:
                out.append(cur); cur = ""
            else: cur += ch
        out.append(cur); return out
    header = [h.lower().strip() for h in parse_line(lines[0])]
    try:
        idx_nama = header.index("nama")
        idx_user = header.index("username")
        idx_kelas = header.index("kelas")
        idx_pass = header.index("password")
    except ValueError:
        conn.close(); return jsonify({"ok": False, "msg": "Header harus: nama,username,kelas,password"}), 400
    berhasil, gagal = 0, 0
    errors = []
    for i, line in enumerate(lines[1:], start=2):
        cols = parse_line(line)
        if len(cols) < 4:
            gagal += 1; errors.append(f"Baris {i}: kolom kurang"); continue
        nama = cols[idx_nama].strip()
        username = cols[idx_user].strip()
        kelas = cols[idx_kelas].strip().upper()
        password = cols[idx_pass].strip()
        if not all([nama, username, kelas, password]):
            gagal += 1; errors.append(f"Baris {i}: data kosong"); continue
        if len(password) < 6:
            gagal += 1; errors.append(f"Baris {i}: password < 6"); continue
        if kelas not in DAFTAR_KELAS:
            gagal += 1; errors.append(f"Baris {i}: kelas '{kelas}' invalid"); continue
        if conn.execute("SELECT 1 FROM users WHERE LOWER(username)=?", (username.lower(),)).fetchone():
            gagal += 1; errors.append(f"Baris {i}: username '{username}' sudah ada"); continue
        try:
            conn.execute("""INSERT INTO users (username,nama,password,role,sekolah_id,kelas,qr_token,created_at,email,no_wa)
                            VALUES (?,?,?,?,?,?,?,?,?,?)""",
                         (username, nama, generate_password_hash(password), "siswa",
                          user["sekolah_id"], kelas, gen_token(), datetime.now().isoformat(), "", ""))
            berhasil += 1
        except:
            gagal += 1
    conn.commit(); conn.close()
    return jsonify({"ok": True, "berhasil": berhasil, "gagal": gagal, "errors": errors[:10]})

# ============================================================
# API: ABSEN (SCAN)
# ============================================================
@app.route("/api/scan", methods=["POST"])
@login_required
@guru_required
def api_scan():
    d = request.get_json() or {}
    token = (d.get("token") or "").strip().upper()
    status_pilih = d.get("status") or "Hadir"
    if not token: return jsonify({"ok": False, "msg": "Token kosong"}), 400
    conn = get_db()
    guru = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    user = conn.execute("SELECT * FROM users WHERE qr_token=? AND role='siswa' AND sekolah_id=?",
                        (token, guru["sekolah_id"])).fetchone()
    if not user:
        conn.close(); return jsonify({"ok": False, "msg": "QR tidak dikenali ❌"}), 404
    tgl = today()
    if cek_hari_libur(conn, guru["sekolah_id"], tgl):
        conn.close(); return jsonify({"ok": False, "msg": "🎉 Hari libur"}), 400
    sekolah = conn.execute("SELECT * FROM sekolah WHERE id=?", (guru["sekolah_id"],)).fetchone()
    batas = sekolah["jam_batas_masuk"] or "07:15"
    jpm = sekolah["jam_pulang_mulai"] or "13:00"
    sekarang = jam_short()
    sudah = conn.execute("SELECT * FROM absensi WHERE user_id=? AND tanggal=?", (user["id"], tgl)).fetchone()
    if sudah and sudah["jam_pulang"]:
        conn.close()
        return jsonify({"ok": False, "msg": f"⚠️ {user['nama']} sudah absen lengkap"})
    if sudah and not sudah["jam_pulang"]:
        if sekarang < jpm:
            conn.close()
            return jsonify({"ok": False, "msg": f"⏱️ Sudah masuk. Belum waktunya pulang (mulai {jpm})"})
        conn.execute("UPDATE absensi SET jam_pulang=? WHERE id=?", (now_jam(), sudah["id"]))
        conn.commit(); conn.close()
        return jsonify({"ok": True, "nama": user["nama"], "jam": now_jam(), "status": "Pulang",
                        "msg": f"👋 {user['nama']} — PULANG"})
    telat = 1 if sekarang > batas else 0
    status_final = "Terlambat" if (status_pilih == "Hadir" and telat) else status_pilih
    menit_telat = hitung_terlambat(batas, sekarang) if telat else 0
    try:
        conn.execute("""INSERT INTO absensi (user_id, tanggal, jam_masuk, status, terlambat)
                        VALUES (?,?,?,?,?)""", (user["id"], tgl, now_jam(), status_final, telat))
        conn.commit(); conn.close()
        return jsonify({"ok": True, "nama": user["nama"], "jam": now_jam(),
                        "status": status_final, "menit_terlambat": menit_telat,
                        "msg": f"✅ {user['nama']} — {status_final}"})
    except sqlite3.IntegrityError:
        conn.close(); return jsonify({"ok": False, "msg": "Sudah absen"})

@app.route("/api/absen-manual", methods=["POST"])
@login_required
@guru_required
def api_absen_manual():
    d = request.get_json() or {}
    uid = d.get("user_id")
    status_pilih = d.get("status") or "Hadir"
    conn = get_db()
    guru = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    user = conn.execute("SELECT * FROM users WHERE id=? AND sekolah_id=?", (uid, guru["sekolah_id"])).fetchone()
    if not user:
        conn.close(); return jsonify({"ok": False, "msg": "User tidak ditemukan"}), 404
    tgl = today()
    if cek_hari_libur(conn, guru["sekolah_id"], tgl):
        conn.close(); return jsonify({"ok": False, "msg": "🎉 Hari libur"}), 400
    sekolah = conn.execute("SELECT * FROM sekolah WHERE id=?", (guru["sekolah_id"],)).fetchone()
    batas = sekolah["jam_batas_masuk"] or "07:15"
    jpm = sekolah["jam_pulang_mulai"] or "13:00"
    sudah = conn.execute("SELECT * FROM absensi WHERE user_id=? AND tanggal=?", (uid, tgl)).fetchone()
    if not sudah:
        telat = 1 if jam_short() > batas else 0
        status_final = "Terlambat" if (status_pilih == "Hadir" and telat) else status_pilih
        menit = hitung_terlambat(batas, jam_short()) if telat else 0
        conn.execute("""INSERT INTO absensi (user_id, tanggal, jam_masuk, status, terlambat)
                        VALUES (?,?,?,?,?)""", (uid, tgl, now_jam(), status_final, telat))
        conn.commit(); conn.close()
        return jsonify({"ok": True, "nama": user["nama"], "jam": now_jam(),
                        "status": status_final, "menit_terlambat": menit,
                        "msg": f"✅ {user['nama']} — {status_final}"})
    elif not sudah["jam_pulang"]:
        if jam_short() < jpm:
            conn.close(); return jsonify({"ok": False, "msg": f"⏱️ Belum waktunya pulang (mulai {jpm})"})
        conn.execute("UPDATE absensi SET jam_pulang=? WHERE id=?", (now_jam(), sudah["id"]))
        conn.commit(); conn.close()
        return jsonify({"ok": True, "nama": user["nama"], "jam": now_jam(), "status": "Pulang",
                        "msg": f"👋 {user['nama']} — PULANG"})
    conn.close(); return jsonify({"ok": False, "msg": "Sudah absen lengkap"})

# ============================================================
# API: RIWAYAT & LAPORAN
# ============================================================
@app.route("/api/riwayat")
@login_required
def api_riwayat():
    conn = get_db()
    rows = conn.execute("""SELECT * FROM absensi WHERE user_id=? ORDER BY tanggal DESC LIMIT 90""",
                        (session["user_id"],)).fetchall()
    conn.close()
    return jsonify({"ok": True, "data": [dict(r) for r in rows]})

@app.route("/api/laporan")
@login_required
@guru_required
def api_laporan():
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    rows = conn.execute("""SELECT a.*, u.nama as nama_siswa, u.kelas as kelas_siswa
                           FROM absensi a JOIN users u ON u.id=a.user_id
                           WHERE u.sekolah_id=? ORDER BY a.tanggal DESC, a.jam_masuk DESC LIMIT 300""",
                        (user["sekolah_id"],)).fetchall()
    conn.close()
    return jsonify({"ok": True, "data": [dict(r) for r in rows]})

@app.route("/api/kelola/hapus/<int:aid>", methods=["DELETE"])
@login_required
@guru_required
def api_kelola_hapus(aid):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    a = conn.execute("""SELECT a.* FROM absensi a JOIN users u ON u.id=a.user_id
                        WHERE a.id=? AND u.sekolah_id=?""", (aid, user["sekolah_id"])).fetchone()
    if not a: conn.close(); return jsonify({"ok": False, "msg": "Tidak ditemukan"}), 404
    conn.execute("DELETE FROM absensi WHERE id=?", (aid,)); conn.commit(); conn.close()
    return jsonify({"ok": True, "msg": "Dihapus"})

@app.route("/api/kelola/reset-hari-ini", methods=["DELETE"])
@login_required
@guru_required
def api_reset_hari_ini():
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    conn.execute("""DELETE FROM absensi WHERE tanggal=? AND user_id IN
                    (SELECT id FROM users WHERE sekolah_id=?)""", (today(), user["sekolah_id"]))
    conn.commit(); conn.close()
    return jsonify({"ok": True, "msg": "Reset berhasil"})

@app.route("/api/export-laporan")
@login_required
@guru_required
def api_export_laporan():
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    rows = conn.execute("""SELECT a.tanggal, u.nama, u.kelas, a.jam_masuk, a.jam_pulang, a.status, a.terlambat
                           FROM absensi a JOIN users u ON u.id=a.user_id
                           WHERE u.sekolah_id=? ORDER BY a.tanggal DESC, a.jam_masuk DESC""",
                        (user["sekolah_id"],)).fetchall()
    conn.close()
    buf = io.StringIO(); w = csv.writer(buf)
    w.writerow(["Tanggal","Nama","Kelas","Jam Masuk","Jam Pulang","Status","Terlambat"])
    for r in rows:
        w.writerow([r["tanggal"], r["nama"], r["kelas"] or "", r["jam_masuk"] or "",
                    r["jam_pulang"] or "", r["status"], "Ya" if r["terlambat"] else "Tidak"])
    mem = io.BytesIO(buf.getvalue().encode("utf-8-sig")); mem.seek(0)
    return send_file(mem, mimetype="text/csv", as_attachment=True,
                     download_name=f"laporan_{today()}.csv")

# ============================================================
# API: HARI LIBUR
# ============================================================
@app.route("/api/libur", methods=["GET"])
@login_required
@guru_required
def api_libur_list():
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    rows = conn.execute("SELECT * FROM hari_libur WHERE sekolah_id=? ORDER BY tanggal",
                        (user["sekolah_id"],)).fetchall()
    conn.close()
    return jsonify({"ok": True, "data": [dict(r) for r in rows]})

@app.route("/api/libur", methods=["POST"])
@login_required
@admin_required
def api_libur_add():
    d = request.get_json() or {}
    tgl = d.get("tanggal")
    ket = (d.get("keterangan") or "Hari Libur").strip()
    if not tgl: return jsonify({"ok": False, "msg": "Pilih tanggal"}), 400
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    try:
        conn.execute("INSERT INTO hari_libur (sekolah_id, tanggal, keterangan) VALUES (?,?,?)",
                     (user["sekolah_id"], tgl, ket))
        conn.commit(); conn.close()
        return jsonify({"ok": True, "msg": "Hari libur ditambah"})
    except sqlite3.IntegrityError:
        conn.close(); return jsonify({"ok": False, "msg": "Tanggal sudah ada"}), 400

@app.route("/api/libur/<int:lid>", methods=["DELETE"])
@login_required
@admin_required
def api_libur_hapus(lid):
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    conn.execute("DELETE FROM hari_libur WHERE id=? AND sekolah_id=?", (lid, user["sekolah_id"]))
    conn.commit(); conn.close()
    return jsonify({"ok": True})

# ============================================================
# API: PENGAJUAN IZIN
# ============================================================
@app.route("/api/izin", methods=["GET"])
@login_required
def api_izin_list():
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    if user["role"] == "siswa":
        rows = conn.execute("SELECT id,jenis,keterangan,foto,tanggal,status,review_note FROM pengajuan_izin WHERE user_id=? ORDER BY id DESC",
                            (user["id"],)).fetchall()
    else:
        rows = conn.execute("""SELECT p.*, u.nama as nama_siswa, u.kelas as kelas_siswa
                               FROM pengajuan_izin p JOIN users u ON u.id=p.user_id
                               WHERE p.sekolah_id=? ORDER BY p.status='pending' DESC, p.id DESC""",
                            (user["sekolah_id"],)).fetchall()
    conn.close()
    return jsonify({"ok": True, "data": [dict(r) for r in rows]})

@app.route("/api/izin", methods=["POST"])
@login_required
def api_izin_add():
    d = request.get_json() or {}
    if session.get("role") != "siswa":
        return jsonify({"ok": False, "msg": "Hanya siswa yang bisa ajukan"}), 403
    tanggal = d.get("tanggal")
    jenis = d.get("jenis") or "Izin"
    ket = (d.get("keterangan") or "").strip()
    foto = d.get("foto") or ""
    if not tanggal or not foto:
        return jsonify({"ok": False, "msg": "Tanggal & foto wajib"}), 400
    if len(foto) > 1500000:
        return jsonify({"ok": False, "msg": "Foto terlalu besar"}), 400
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    conn.execute("""INSERT INTO pengajuan_izin (user_id,sekolah_id,jenis,keterangan,foto,tanggal,status,created_at)
                    VALUES (?,?,?,?,?,?,?,?)""",
                 (user["id"], user["sekolah_id"], jenis, ket, foto, tanggal, "pending", datetime.now().isoformat()))
    conn.commit(); conn.close()
    return jsonify({"ok": True, "msg": "Pengajuan terkirim, tunggu konfirmasi"})

@app.route("/api/izin/<int:pid>/approve", methods=["POST"])
@login_required
@guru_required
def api_izin_approve(pid):
    conn = get_db()
    guru = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    p = conn.execute("SELECT * FROM pengajuan_izin WHERE id=? AND sekolah_id=?", (pid, guru["sekolah_id"])).fetchone()
    if not p or p["status"] != "pending":
        conn.close(); return jsonify({"ok": False, "msg": "Sudah diproses"}), 400
    sudah = conn.execute("SELECT * FROM absensi WHERE user_id=? AND tanggal=?", (p["user_id"], p["tanggal"])).fetchone()
    if sudah and sudah["jam_pulang"]:
        conn.close(); return jsonify({"ok": False, "msg": "Siswa sudah absen lengkap"}), 400
    if sudah:
        conn.execute("UPDATE absensi SET status=?, terlambat=0 WHERE id=?", (p["jenis"], sudah["id"]))
    else:
        conn.execute("""INSERT INTO absensi (user_id,tanggal,jam_masuk,status,terlambat,via_izin)
                        VALUES (?,?,?,?,?,?)""", (p["user_id"], p["tanggal"], "-", p["jenis"], 0, 1))
    conn.execute("UPDATE pengajuan_izin SET status='approved', reviewed_by=?, reviewed_at=? WHERE id=?",
                 (guru["id"], datetime.now().isoformat(), pid))
    conn.commit(); conn.close()
    return jsonify({"ok": True, "msg": "Disetujui"})

@app.route("/api/izin/<int:pid>/reject", methods=["POST"])
@login_required
@guru_required
def api_izin_reject(pid):
    d = request.get_json() or {}
    note = (d.get("note") or "").strip()
    conn = get_db()
    guru = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    p = conn.execute("SELECT * FROM pengajuan_izin WHERE id=? AND sekolah_id=?", (pid, guru["sekolah_id"])).fetchone()
    if not p or p["status"] != "pending":
        conn.close(); return jsonify({"ok": False, "msg": "Sudah diproses"}), 400
    conn.execute("""UPDATE pengajuan_izin SET status='rejected', reviewed_by=?, reviewed_at=?, review_note=?
                    WHERE id=?""", (guru["id"], datetime.now().isoformat(), note, pid))
    conn.commit(); conn.close()
    return jsonify({"ok": True, "msg": "Ditolak"})

# ============================================================
# API: PENGATURAN
# ============================================================
@app.route("/api/pengaturan", methods=["POST"])
@login_required
@admin_required
def api_pengaturan():
    d = request.get_json() or {}
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    conn.execute("""UPDATE sekolah SET nama=?, jam_batas_masuk=?, jam_pulang_mulai=? WHERE id=?""",
                 ((d.get("nama") or "").strip(),
                  d.get("jam_batas_masuk") or "07:15",
                  d.get("jam_pulang_mulai") or "13:00",
                  user["sekolah_id"]))
    conn.commit(); conn.close()
    return jsonify({"ok": True, "msg": "Pengaturan disimpan"})

@app.route("/api/pengaturan/ganti-kode-guru", methods=["POST"])
@login_required
@admin_required
def api_ganti_kode_guru():
    d = request.get_json() or {}
    baru = (d.get("kode") or "").strip()
    if len(baru) < 4: return jsonify({"ok": False, "msg": "Kode minimal 4 karakter"}), 400
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE id=?", (session["user_id"],)).fetchone()
    conn.execute("UPDATE sekolah SET kode_guru=? WHERE id=?", (baru, user["sekolah_id"]))
    conn.commit(); conn.close()
    return jsonify({"ok": True, "msg": "Kode guru diganti"})

# ============================================================
if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=False)
else:
    init_db()
