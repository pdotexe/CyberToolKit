    import sys
    from PyQt5.QtWidgets import QApplication, QWidget, QPushButton, QLabel, QVBoxLayout
    from PyQt5.QtGui import QFont
    from PyQt5.QtCore import Qt
    import re
    from PyQt5.QtWidgets import QInputDialog, QMessageBox, QFileDialog
    import hashlib
    import os
    import socket
    import time


    class CyberToolkitGUI(QWidget):
        def __init__(self):
            super().__init__()
            self.pass_button.clicked.connect(self.check_password_strength)
            self.hash_button.clicked.connect(self.handle_hash_checker)
            self.port_button.clicked.connect(self.handle_port_scanner)
            # window title + size
            self.setWindowTitle("CyberToolKit")
            self.setGeometry(100, 100, 600, 400)

            # title 
            self.title = QLabel("CyberToolKit", self)
            self.title.setFont(QFont("Arial", 24))
            self.title.setAlignment(Qt.AlignCenter)

            self.pass_button = QPushButton("🔐Password Strength Checker", self)
            self.hash_button = QPushButton("📂File Hash Checker", self)
            self.port_button = QPushButton("🌐Port Scanner", self)
            self.exit_button = QPushButton("Exit", self)

            self.status = QLabel("Working...", self)
            self.status.setAlignment(Qt.AlignCenter)
            self.status.setStyleSheet("color: gray")
            self.status.setFont(QFont("Arial", 12))

            layout = QVBoxLayout()
            layout.addWidget(self.title)
            layout.addWidget(self.pass_button)
            layout.addWidget(self.hash_button)
            layout.addWidget(self.port_button)
            layout.addWidget(self.exit_button)
            layout.addWidget(self.status)

            self.setLayout(layout)
    def check_password_strength(self):
        password, ok = QInputDialog.getText(self, "Password Checker", "Enter a password:")
        if ok and password:
            score = 0
            if len(password) >= 8:
                score += 2
            if re.search(r"[A-Z]", password):
                score += 2
            if re.search(r"[a-z]", password):
                score += 1
            if re.search(r"\d", password):
                score += 3
            if re.search(r"[!@#$%^&*(),.?\":{}|<>]", password):
                score += 4

            if score <= 4:
                result = " Weak"
            elif 5 <= score < 8:
                result = " Moderate"
            else:
                result = " Strong"

            QMessageBox.information(self, "Password Strength", f"Password Strength: {result}")
    def handle_hash_checker(self):
        file_path, _ = QFileDialog.getOpenFileName(self, "Select a file to hash", "", "All Files (*)")
        if not file_path:
            self.status.setText("No file selected.")
            return
        algorithms = ["md5", "sha1", "sha256"]
        algo, ok = QInputDialog.getItem(self, "Select hash algorithm", "choose an algorithm", algorithms, 2, False)
        if not ok or not algo:
            self.stattus.setText("No algorithm selected.")
            return
        try:
            hash_func = getattr(hashlib, algo)()
            with open(file_path, "rb") as file:
                while chunk := file.read(4096):
                    hash_func.update(chunk)
            hash_value = hash_func.hexdigest()
            QMessageBox.information(self, "File Hash", f"{algo.upper()} Hash: {hash_value}")
            self.status.setText("Hash calculated successfully.")
        except Exception as e:
            QMessageBox.critical(self, "Error", f"Error calculating hash: {str(e)}")
            self.status.setText("Error during hash processing.")
    def handle_port_scanner(self):
        target, ok = QInputDialog.getText(self, "Port Scanner", "Enter the target IP address:")
        if not ok or not target:
            self.status.setText("No target IP address provided.")
            return
        
        protocol, ok = QInputDialog.getItem(self, "Enter Protocol", "Choose a protocol:", [ "TCP", "UDP"])
        if not ok or not protocol:
            self.status.setText("No Protocol Selected")
            return
        self.status.setText(f"Scanning {target} on {protocol} ")
        
        open_ports = []
    
        for port in range(1, 1025):
            try:
                if protocol.upper() == "TCP":
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(0.5)
                    result = sock.connect_ex((target, port))
                    if result == 0:
                    open_ports.append(port)
                elif protocol.upper() == "UDP":
                    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    sock.settimeout(0.5)
                try:
                    sock.sendto(b'', (target, port))
                    sock.recvfrom(1024)
                    open_ports.append(port)
                except Exception:
                    pass
                finally:
                    sock.close()
            except Exception as e:
                print(f"Error scanning port {port}: {e}")
        
        
        if open_ports:
            ports = "\n".join(f"Port {port} is open" for port in open_ports)
        else:
            ports_text="No open ports found"

            QMessageBox.information(self, "Scan Results", ports_text )
            self.status.setText("Scan complete.")
    if __name__ == "__main__":
        app = QApplication(sys.argv)
        window = CyberToolkitGUI()
        window.show()
        sys.exit(app.exec_())