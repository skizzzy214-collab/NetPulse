import os
import json
import platform
import subprocess
from datetime import datetime
from flask import Flask, render_template, request, redirect, url_for, flash
from flask_login import LoginManager, UserMixin, login_user, logout_user, login_required, current_user
from sqlalchemy import create_engine, Column, Integer, String, Float, DateTime, Text, ForeignKey
from sqlalchemy.orm import declarative_base, sessionmaker, relationship
from passlib.hash import pbkdf2_sha256
import speedtest

# ========================
# CONFIGURACIÓN GENERAL
# ========================
app = Flask(__name__)
app.secret_key = "clave-secreta-super-segura"

DB_URL = "sqlite:///network_tests.db"
engine = create_engine(DB_URL, connect_args={"check_same_thread": False})
Base = declarative_base()
Session = sessionmaker(bind=engine)
db = Session()

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = "login"

# ========================
# MODELOS DE BASE DE DATOS
# ========================
class User(Base, UserMixin):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True)
    username = Column(String(50), unique=True)
    password_hash = Column(String(200))
    tests = relationship("TestResult", back_populates="user")

    def verify_password(self, password):
        return pbkdf2_sha256.verify(password, self.password_hash)


class TestResult(Base):
    __tablename__ = "test_results"
    id = Column(Integer, primary_key=True)
    user_id = Column(Integer, ForeignKey("users.id"))
    target_ip = Column(String(100))
    ping_ms = Column(Float)
    download_bps = Column(Float)
    upload_bps = Column(Float)
    timestamp = Column(DateTime, default=datetime.utcnow)
    detail_json = Column(Text)
    user = relationship("User", back_populates="tests")


Base.metadata.create_all(engine)

# ========================
# UTILIDADES
# ========================
def run_ping(target, count=4):
    """Ejecuta ping al host/IP y devuelve latencia promedio (ms)."""
    system = platform.system().lower()
    cmd = ["ping", "-n" if system == "windows" else "-c", str(count), target]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        out = proc.stdout
        if "Average" in out:  # Windows
            for line in out.splitlines():
                if "Average" in line:
                    val = "".join(ch for ch in line if ch.isdigit() or ch == ".")
                    return float(val)
        elif "avg" in out or "rtt min/avg" in out:  # Linux/macOS
            for line in out.splitlines():
                if "rtt" in line or "avg" in line:
                    return float(line.split("/")[4])
    except Exception:
        return None
    return None


def run_speedtest():
    """Ejecuta speedtest-cli con manejo de errores y logs en consola."""
    try:
        print("🔍 Iniciando prueba de velocidad...")
        st = speedtest.Speedtest()
        st.get_best_server()
        print("✅ Servidor encontrado:", st.best['host'])
        download = st.download()
        upload = st.upload(pre_allocate=False)
        ping = st.results.ping
        print(f"📊 Resultado - Ping: {ping} ms | Bajada: {download} bps | Subida: {upload} bps")
        return {
            "download": download,
            "upload": upload,
            "ping": ping,
            "raw": st.results.dict(),
        }
    except Exception as e:
        print(f"❌ Error ejecutando speedtest: {e}")
        return {"error": str(e)}

# ========================
# LOGIN MANAGER
# ========================
@login_manager.user_loader
def load_user(user_id):
    return db.get(User, int(user_id))

# ========================
# RUTAS WEB
# ========================

@app.route("/")
def index():
    """Página de inicio."""
    if current_user.is_authenticated:
        return redirect(url_for("dashboard"))
    return render_template("index.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Registro de usuario (se guarda en la base de datos)."""
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        # Verificar si ya existe
        if db.query(User).filter_by(username=username).first():
            flash("❌ El usuario ya existe.", "danger")
            return redirect(url_for("register"))

        # Crear usuario nuevo
        hashed_password = pbkdf2_sha256.hash(password)
        new_user = User(username=username, password_hash=hashed_password)

        # Guardar en la base de datos
        db.add(new_user)
        db.commit()

        flash("✅ Registro exitoso. Ahora puedes iniciar sesión.", "success")
        return redirect(url_for("login"))

    return render_template("register.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    """Inicio de sesión."""
    if request.method == "POST":
        username = request.form["username"]
        password = request.form["password"]

        user = db.query(User).filter_by(username=username).first()

        if not user or not user.verify_password(password):
            flash("❌ Usuario o contraseña incorrectos.", "danger")
            return redirect(url_for("login"))

        login_user(user)
        return redirect(url_for("dashboard"))

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    """Cerrar sesión."""
    logout_user()
    flash("Has cerrado sesión correctamente.", "info")
    return redirect(url_for("index"))


@app.route("/dashboard")
@login_required
def dashboard():
    """Panel principal: muestra las pruebas guardadas."""
    tests = (
        db.query(TestResult)
        .filter_by(user_id=current_user.id)
        .order_by(TestResult.timestamp.desc())
        .all()
    )
    return render_template("dashboard.html", tests=tests)


@app.route("/newtest", methods=["GET", "POST"])
@login_required
def newtest():
    """Crea una nueva prueba de red."""
    if request.method == "POST":
        ip = request.form["ip"]
        ping_ms = run_ping(ip)
        st = run_speedtest()

        if "error" in st:
            flash("⚠️ Error ejecutando speedtest.", "danger")
            return redirect(url_for("dashboard"))

        result = TestResult(
            user_id=current_user.id,
            target_ip=ip,
            ping_ms=ping_ms,
            download_bps=st["download"],
            upload_bps=st["upload"],
            detail_json=json.dumps(st["raw"], indent=2),
        )

        db.add(result)
        db.commit()

        flash("✅ Prueba completada y guardada en la base de datos.", "success")
        return redirect(url_for("dashboard"))

    return render_template("newtest.html")


@app.route("/result/<int:test_id>")
@login_required
def result(test_id):
    """Detalle de una prueba individual."""
    test = db.query(TestResult).filter_by(id=test_id, user_id=current_user.id).first()
    if not test:
        flash("Resultado no encontrado.", "danger")
        return redirect(url_for("dashboard"))
    return render_template("result.html", test=test)


# ========================
# EJECUCIÓN
# ========================
if __name__ == "__main__":
    print("✅ Servidor iniciado en http://127.0.0.1:5000")
    app.run(host="0.0.0.0", port=5000, debug=True)
