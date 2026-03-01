import os
import sys
import json
from PyQt6.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit,
    QPushButton, QTextEdit, QVBoxLayout,
    QHBoxLayout, QComboBox, QFileDialog
)
from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtGui import QTextCursor
from PyQt6.QtGui import QPixmap
from PyQt6.QtCore import Qt
from PyQt6.QtGui import QIcon
from PyQt6.QtWidgets import QListWidget
from PyQt6.QtWidgets import QSplitter
from scanner import scan_ports


# ------------------------------
# Worker Thread
# ------------------------------

class ScanWorker(QThread):
    finished = pyqtSignal(dict)

    def __init__(self, target, start_port, end_port, scan_type):
        super().__init__()
        self.target = target
        self.start_port = start_port
        self.end_port = end_port
        self.scan_type = scan_type

    def run(self):
        results = scan_ports(
            self.target,
            self.start_port,
            self.end_port,
            self.scan_type
        )
        self.finished.emit(results)


# ------------------------------
# GUI
# ------------------------------

class HopeScanGUI(QWidget):

    def __init__(self):
        super().__init__()

        self.setWindowTitle("HopeScan")
        self.setGeometry(200, 200, 950, 650)

        self.setWindowIcon(QIcon("assets/hopescan.ico"))

        self.results_data = None
        self.scan_history = []

        self.setStyleSheet(self.dark_theme())

        layout = QVBoxLayout()
        input_layout = QHBoxLayout()
        port_layout = QHBoxLayout()

        # Logo
        self.logo_label = QLabel()
        pixmap = QPixmap("assets/logo.png")
        self.logo_label.setPixmap(pixmap.scaledToHeight(60))
        self.logo_label.setAlignment(Qt.AlignmentFlag.AlignCenter)

        layout.addWidget(self.logo_label)

        self.ip_input = QLineEdit()
        self.ip_input.setPlaceholderText("Target IP or Domain")

        self.scan_type = QComboBox()
        self.scan_type.addItems(["Basic", "Enumeration"])

        self.start_port_input = QLineEdit()
        self.start_port_input.setPlaceholderText("Start Port (1)")

        self.end_port_input = QLineEdit()
        self.end_port_input.setPlaceholderText("End Port (1024)")

        self.scan_button = QPushButton("Start Scan")
        self.scan_button.clicked.connect(self.start_scan)
        self.toggle_history_button = QPushButton("Hide History")
        self.toggle_history_button.clicked.connect(self.toggle_history)

        self.save_button = QPushButton("Save Results")
        self.save_button.clicked.connect(self.save_results)
        self.save_button.setEnabled(False)

        self.output = QTextEdit()
        self.output.setReadOnly(True)

        input_layout.addWidget(QLabel("Target"))
        input_layout.addWidget(self.ip_input)
        input_layout.addWidget(self.scan_type)
        input_layout.addWidget(self.scan_button)
        input_layout.addWidget(self.toggle_history_button)
        input_layout.addWidget(self.save_button)

        port_layout.addWidget(QLabel("Ports"))
        port_layout.addWidget(self.start_port_input)
        port_layout.addWidget(self.end_port_input)

        # Create splitter
        splitter = QSplitter(Qt.Orientation.Horizontal)

        # ----- Left Panel (History) -----
        left_widget = QWidget()
        left_layout = QVBoxLayout()

        self.history_list = QListWidget()
        self.history_list.itemClicked.connect(self.load_history_scan)

        left_layout.addWidget(QLabel("Scan History"))
        left_layout.addWidget(self.history_list)
        left_widget.setLayout(left_layout)

        # ----- Right Panel (Main Content) -----
        right_widget = QWidget()
        right_layout = QVBoxLayout()

        right_layout.addWidget(self.logo_label)
        right_layout.addLayout(input_layout)
        right_layout.addLayout(port_layout)
        right_layout.addWidget(self.output)

        right_widget.setLayout(right_layout)

        # Add to splitter
        splitter.addWidget(left_widget)
        splitter.addWidget(right_widget)

        # Make right side expand more
        splitter.setStretchFactor(0, 1)  # history
        splitter.setStretchFactor(1, 4)  # output

        # Set initial size ratio
        splitter.setSizes([250, 700])

        # Final layout
        main_layout = QVBoxLayout()
        main_layout.addWidget(splitter)

        self.setLayout(main_layout)

        # Store reference for toggle use
        self.splitter = splitter
        self.left_widget = left_widget


    def toggle_history(self):
        if self.left_widget.isVisible():
            self.left_widget.hide()
            self.toggle_history_button.setText("Show History")
        else:
            self.left_widget.show()
            self.toggle_history_button.setText("Hide History")


    # ------------------------------
    # Theme
    # ------------------------------
    def dark_theme(self):
        return """
        QWidget {
            background-color: #0f0f0f;
            color: #e6e6e6;
            font-family: Consolas;
            font-size: 13px;
        }

        QLineEdit, QTextEdit, QComboBox {
            background-color: #1a1a1a;
            border: 1px solid #333;
            padding: 6px;
        }

        QPushButton {
            background-color: #ff7a00;
            border: none;
            padding: 8px;
            font-weight: bold;
        }

        QPushButton:hover {
            background-color: #ff9500;
        }

        QPushButton:disabled {
            background-color: #333;
            color: #777;
        }
        """

    # ------------------------------
    # CVSS Colour Logic
    # ------------------------------

    def cvss_colour(self, score):
        try:
            score = float(score)
        except:
            return "#999999"

        if score == 0:
            return "#999999"
        elif score < 4:
            return "#2ecc71"
        elif score < 7:
            return "#f1c40f"
        elif score < 9:
            return "#ff7a00"
        else:
            return "#e74c3c"

    # ------------------------------
    # Start Scan
    # ------------------------------

    def start_scan(self):

        target = self.ip_input.text().strip()
        scan_type = self.scan_type.currentText()

        if not target:
            return

        start_port = int(self.start_port_input.text()) if self.start_port_input.text() else 1
        end_port = int(self.end_port_input.text()) if self.end_port_input.text() else 1024

        self.output.clear()
        self.output.append(f"<span style='color:#ff7a00;'>Scanning {target} ({start_port}-{end_port})...</span><br>")

        self.scan_button.setEnabled(False)
        self.save_button.setEnabled(False)

        self.worker = ScanWorker(target, start_port, end_port, scan_type)
        self.worker.finished.connect(self.display_results)
        self.worker.start()

    # ------------------------------
    # Display Results
    # ------------------------------

    def display_results(self, results, add_to_history=True):

        self.results_data = results

        if add_to_history:
            summary = f"{results['target']} | {len(results['ports'])} ports"
            self.scan_history.append(results)
            self.history_list.addItem(summary)

        if results["ports"]:
            for entry in results["ports"]:

                self.output.append(
                    f"<b>Port {entry['port']}</b> | {entry['service']} | {entry['version']}<br>"
                )

                if entry["cves"]:
                    for cve in entry["cves"][:5]:

                        colour = self.cvss_colour(cve["cvss"])

                        self.output.append(
                            f"&nbsp;&nbsp;<span style='color:{colour};'>"
                            f"{cve['cve']} | CVSS {cve['cvss']}"
                            f"</span> — {cve['summary']}<br>"
                        )
                else:
                    self.output.append("&nbsp;&nbsp;<span style='color:#999;'>No CVEs found.</span><br>")

                self.output.append("<br>")
        else:
            self.output.append("<span style='color:#999;'>No open ports found.</span><br>")

        self.output.append(
            f"<br><span style='color:#ff7a00;'>Scan completed in {results['duration']} seconds.</span>"
        )

        self.scan_button.setEnabled(True)
        self.save_button.setEnabled(True)

    # ------------------------------
    # Save Results
    # ------------------------------

    def load_history_scan(self, item):
        index = self.history_list.row(item)
        results = self.scan_history[index]
        self.display_results(results, add_to_history=False)


    def save_results(self):

        if not self.results_data:
            return

        file_path, _ = QFileDialog.getSaveFileName(
            self,
            "Save Results",
            "hopescan_results.json",
            "JSON Files (*.json)"
        )

        if file_path:
            with open(file_path, "w") as f:
                json.dump(self.results_data, f, indent=4)

            self.output.append("<br><span style='color:#2ecc71;'>Results saved successfully.</span>")


# ------------------------------
# Run
# ------------------------------

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = HopeScanGUI()
    window.show()
    sys.exit(app.exec())