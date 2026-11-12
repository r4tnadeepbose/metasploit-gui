import json
from PyQt6.QtCore import Qt
from PyQt6.QtWidgets import (
    QMainWindow, QWidget, QVBoxLayout, QHBoxLayout, QFormLayout, QLineEdit,
    QPushButton, QLabel, QComboBox, QListWidget, QListWidgetItem, QTextEdit,
    QTabWidget, QTableWidget, QTableWidgetItem, QMessageBox, QSplitter,
    QGroupBox, QCheckBox, QSpinBox, QPlainTextEdit
)

from app.msf_client import MsfRpcClient, MsfRpcError


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Metasploit RPC GUI (Windows)")
        self.resize(1200, 800)
        self.client = None
        self.current_module_type = "exploit"
        self.current_module_name = None
        self._build_ui()

    def _build_ui(self):
        root = QWidget()
        self.setCentralWidget(root)
        layout = QVBoxLayout(root)

        # Connection bar
        conn = QGroupBox("msfrpcd Connection")
        cform = QHBoxLayout(conn)
        self.host_edit = QLineEdit("127.0.0.1")
        self.port_spin = QSpinBox(); self.port_spin.setRange(1, 65535); self.port_spin.setValue(55553)
        self.user_edit = QLineEdit("msf")
        self.pass_edit = QLineEdit(); self.pass_edit.setEchoMode(QLineEdit.EchoMode.Password)
        self.ssl_check = QCheckBox("SSL")
        self.connect_btn = QPushButton("Connect")
        self.disconnect_btn = QPushButton("Disconnect"); self.disconnect_btn.setEnabled(False)
        self.status_label = QLabel("Disconnected")
        for w, label in [(self.host_edit, "Host"), (self.port_spin, "Port"), (self.user_edit, "User"), (self.pass_edit, "Pass")]:
            cform.addWidget(QLabel(label))
            cform.addWidget(w)
        cform.addWidget(self.ssl_check)
        cform.addWidget(self.connect_btn)
        cform.addWidget(self.disconnect_btn)
        cform.addWidget(self.status_label, 1)
        layout.addWidget(conn)

        self.tabs = QTabWidget()
        layout.addWidget(self.tabs, 1)

        self._build_modules_tab()
        self._build_jobs_tab()
        self._build_sessions_tab()

        self.log = QPlainTextEdit(); self.log.setReadOnly(True); self.log.setMaximumHeight(160)
        layout.addWidget(QLabel("Log"))
        layout.addWidget(self.log)

        self.connect_btn.clicked.connect(self.do_connect)
        self.disconnect_btn.clicked.connect(self.do_disconnect)

    # ---- Modules ----
    def _build_modules_tab(self):
        tab = QWidget()
        v = QVBoxLayout(tab)
        top = QHBoxLayout()
        self.mtype_combo = QComboBox(); self.mtype_combo.addItems(["exploit", "auxiliary", "post", "payload"])
        self.search_edit = QLineEdit(); self.search_edit.setPlaceholderText("Filter modules...")
        self.refresh_modules_btn = QPushButton("Load Modules")
        top.addWidget(QLabel("Type")); top.addWidget(self.mtype_combo)
        top.addWidget(QLabel("Search")); top.addWidget(self.search_edit, 1)
        top.addWidget(self.refresh_modules_btn)
        v.addLayout(top)

        splitter = QSplitter()
        self.module_list = QListWidget()
        splitter.addWidget(self.module_list)

        right = QWidget(); rv = QVBoxLayout(right)
        self.mod_title = QLabel("Select a module"); self.mod_title.setWordWrap(True)
        rv.addWidget(self.mod_title)
        self.mod_info = QTextEdit(); self.mod_info.setReadOnly(True)
        rv.addWidget(self.mod_info, 2)
        rv.addWidget(QLabel("Options (JSON object passed to module.execute):"))
        self.options_edit = QPlainTextEdit()
        self.options_edit.setPlaceholderText('{\n  "RHOSTS": "192.168.1.10",\n  "RPORT": 445\n}')
        rv.addWidget(self.options_edit, 1)
        run_row = QHBoxLayout()
        self.payload_edit = QLineEdit(); self.payload_edit.setPlaceholderText("Payload (for exploits, optional)")
        self.run_btn = QPushButton("Run Module")
        run_row.addWidget(QLabel("Payload")); run_row.addWidget(self.payload_edit, 1); run_row.addWidget(self.run_btn)
        rv.addLayout(run_row)
        splitter.addWidget(right)
        splitter.setSizes([350, 800])
        v.addWidget(splitter, 1)
        self.tabs.addTab(tab, "Modules")

        self.refresh_modules_btn.clicked.connect(self.load_modules)
        self.search_edit.textChanged.connect(self.filter_modules)
        self.module_list.currentItemChanged.connect(self.on_module_selected)
        self.run_btn.clicked.connect(self.run_module)
        self._all_modules = []

    def _build_jobs_tab(self):
        tab = QWidget(); v = QVBoxLayout(tab)
        row = QHBoxLayout()
        self.refresh_jobs_btn = QPushButton("Refresh Jobs")
        self.stop_job_btn = QPushButton("Stop Selected Job")
        row.addWidget(self.refresh_jobs_btn); row.addWidget(self.stop_job_btn); row.addStretch(1)
        v.addLayout(row)
        self.jobs_table = QTableWidget(0, 2)
        self.jobs_table.setHorizontalHeaderLabels(["Job ID", "Name/Info"])
        self.jobs_table.horizontalHeader().setStretchLastSection(True)
        v.addWidget(self.jobs_table)
        self.tabs.addTab(tab, "Jobs")
        self.refresh_jobs_btn.clicked.connect(self.load_jobs)
        self.stop_job_btn.clicked.connect(self.stop_selected_job)

    def _build_sessions_tab(self):
        tab = QWidget(); v = QVBoxLayout(tab)
        row = QHBoxLayout()
        self.refresh_sessions_btn = QPushButton("Refresh Sessions")
        row.addWidget(self.refresh_sessions_btn); row.addStretch(1)
        v.addLayout(row)
        self.sessions_table = QTableWidget(0, 5)
        self.sessions_table.setHorizontalHeaderLabels(["ID", "Type", "Tunnel", "Via", "Info"])
        self.sessions_table.horizontalHeader().setStretchLastSection(True)
        v.addWidget(self.sessions_table, 1)
        cmd = QGroupBox("Session Command (shell sessions)")
        cv = QVBoxLayout(cmd)
        self.session_cmd_edit = QLineEdit(); self.session_cmd_edit.setPlaceholderText("Command to write to selected shell session")
        btns = QHBoxLayout()
        self.send_cmd_btn = QPushButton("Send"); self.read_cmd_btn = QPushButton("Read Output")
        btns.addWidget(self.session_cmd_edit, 1); btns.addWidget(self.send_cmd_btn); btns.addWidget(self.read_cmd_btn)
        cv.addLayout(btns)
        self.session_output = QPlainTextEdit(); self.session_output.setReadOnly(True)
        cv.addWidget(self.session_output)
        v.addWidget(cmd, 1)
        self.tabs.addTab(tab, "Sessions")
        self.refresh_sessions_btn.clicked.connect(self.load_sessions)
        self.send_cmd_btn.clicked.connect(self.send_session_cmd)
        self.read_cmd_btn.clicked.connect(self.read_session_output)

    # ---- actions ----
    def log_msg(self, msg):
        self.log.appendPlainText(str(msg))

    def require_client(self):
        if not self.client or not self.client.token:
            QMessageBox.warning(self, "Not connected", "Connect to msfrpcd first.")
            return False
        return True

    def do_connect(self):
        host = self.host_edit.text().strip()
        port = self.port_spin.value()
        user = self.user_edit.text().strip()
        pwd = self.pass_edit.text()
        ssl = self.ssl_check.isChecked()
        try:
            self.client = MsfRpcClient(host=host, port=port, ssl=ssl)
            self.client.login(user, pwd)
            ver = {}
            try:
                ver = self.client.core_version() or {}
            except Exception:
                pass
            info = ver.get('version') or ver.get('ruby') or 'connected'
            self.status_label.setText(f"Connected: {info}")
            self.connect_btn.setEnabled(False)
            self.disconnect_btn.setEnabled(True)
            self.log_msg(f"Connected to {host}:{port} (SSL={ssl}) {ver}")
        except Exception as e:
            self.client = None
            QMessageBox.critical(self, "Connection failed", str(e))
            self.log_msg(f"Connection failed: {e}")

    def do_disconnect(self):
        if self.client:
            try:
                self.client.logout()
            except Exception:
                pass
        self.client = None
        self.status_label.setText("Disconnected")
        self.connect_btn.setEnabled(True)
        self.disconnect_btn.setEnabled(False)
        self.log_msg("Disconnected")

    def load_modules(self):
        if not self.require_client():
            return
        mtype = self.mtype_combo.currentText()
        self.current_module_type = mtype
        self.module_list.clear()
        self._all_modules = []
        try:
            modules = self.client.list_modules(mtype)
            if isinstance(modules, dict):
                modules = modules.get('modules', [])
            self._all_modules = sorted([str(m) for m in (modules or [])])
            self.filter_modules()
            self.log_msg(f"Loaded {len(self._all_modules)} {mtype} modules")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
            self.log_msg(f"Failed to load modules: {e}")

    def filter_modules(self):
        q = self.search_edit.text().strip().lower()
        self.module_list.clear()
        for m in self._all_modules:
            if not q or q in m.lower():
                self.module_list.addItem(QListWidgetItem(m))

    def on_module_selected(self, current, _prev):
        if not current or not self.require_client():
            return
        name = current.text()
        self.current_module_name = name
        mtype = self.current_module_type
        self.mod_title.setText(f"{mtype}/{name}")
        try:
            info = self.client.module_info(mtype, name)
            opts = self.client.module_options(mtype, name)
            text = json.dumps(info, indent=2, default=str) + "\n\nOPTIONS:\n" + json.dumps(opts, indent=2, default=str)
            self.mod_info.setPlainText(text)
            # prefill a minimal options template from required opts
            template = {}
            if isinstance(opts, dict):
                for k, v in opts.items():
                    if isinstance(v, dict) and v.get('required') and v.get('default') not in (None, ''):
                        template[k] = v.get('default')
                    elif isinstance(v, dict) and v.get('required'):
                        template[k] = ""
            self.options_edit.setPlainText(json.dumps(template, indent=2))
        except Exception as e:
            self.mod_info.setPlainText(f"Error loading module info: {e}")

    def run_module(self):
        if not self.require_client() or not self.current_module_name:
            return
        mtype = self.current_module_type
        name = self.current_module_name
        try:
            raw = self.options_edit.toPlainText().strip() or "{}"
            options = json.loads(raw)
            if not isinstance(options, dict):
                raise ValueError("Options must be a JSON object")
            payload = self.payload_edit.text().strip()
            if payload:
                options['PAYLOAD'] = payload
            res = self.client.module_execute(mtype, name, options)
            self.log_msg(f"module.execute {mtype}/{name} -> {res}")
            QMessageBox.information(self, "Module executed", json.dumps(res, indent=2, default=str))
            self.load_jobs()
            self.load_sessions()
        except Exception as e:
            QMessageBox.critical(self, "Run failed", str(e))
            self.log_msg(f"Run failed: {e}")

    def load_jobs(self):
        if not self.require_client():
            return
        try:
            jobs = self.client.job_list() or {}
            self.jobs_table.setRowCount(0)
            for jid, jname in jobs.items():
                row = self.jobs_table.rowCount(); self.jobs_table.insertRow(row)
                self.jobs_table.setItem(row, 0, QTableWidgetItem(str(jid)))
                self.jobs_table.setItem(row, 1, QTableWidgetItem(str(jname)))
            self.log_msg(f"Loaded {len(jobs)} jobs")
        except Exception as e:
            self.log_msg(f"Failed to load jobs: {e}")

    def stop_selected_job(self):
        if not self.require_client():
            return
        row = self.jobs_table.currentRow()
        if row < 0:
            return
        jid = self.jobs_table.item(row, 0).text()
        try:
            res = self.client.job_stop(jid)
            self.log_msg(f"job.stop {jid} -> {res}")
            self.load_jobs()
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def load_sessions(self):
        if not self.require_client():
            return
        try:
            sessions = self.client.session_list() or {}
            self.sessions_table.setRowCount(0)
            for sid, info in sessions.items():
                row = self.sessions_table.rowCount(); self.sessions_table.insertRow(row)
                if not isinstance(info, dict):
                    info = {"info": str(info)}
                vals = [str(sid), str(info.get('type','')), str(info.get('tunnel','')), str(info.get('via_exploit','')), str(info.get('info',''))]
                for c, val in enumerate(vals):
                    self.sessions_table.setItem(row, c, QTableWidgetItem(val))
            self.log_msg(f"Loaded {len(sessions)} sessions")
        except Exception as e:
            self.log_msg(f"Failed to load sessions: {e}")

    def _selected_session_id(self):
        row = self.sessions_table.currentRow()
        if row < 0:
            return None
        return self.sessions_table.item(row, 0).text()

    def send_session_cmd(self):
        if not self.require_client():
            return
        sid = self._selected_session_id()
        if not sid:
            QMessageBox.warning(self, "No session", "Select a session first.")
            return
        cmd = self.session_cmd_edit.text()
        try:
            res = self.client.session_shell_write(sid, cmd)
            self.log_msg(f"session.shell_write {sid} -> {res}")
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))

    def read_session_output(self):
        if not self.require_client():
            return
        sid = self._selected_session_id()
        if not sid:
            QMessageBox.warning(self, "No session", "Select a session first.")
            return
        try:
            res = self.client.session_shell_read(sid) or {}
            data = res.get('data', '') if isinstance(res, dict) else str(res)
            self.session_output.setPlainText(str(data))
        except Exception as e:
            QMessageBox.critical(self, "Error", str(e))
