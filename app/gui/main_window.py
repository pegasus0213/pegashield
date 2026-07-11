import os

from PySide6.QtCore import (
    Qt,
    Signal,
)

from PySide6.QtWidgets import (
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from app.core.clamav import (
    CommandWorker,
    database_is_ready,
    find_clamav_directory,
    get_clamav_executable_paths,
    get_clamav_version,
)

from app.core.paths import (
    DATABASE_DIRECTORY,
    FRESHCLAM_CONFIG_PATH,
    initialize_application_data,
)

from app.gui.quarantine_window import (
    QuarantineWindow,
)

from app.services.quarantine import (
    load_quarantine_records,
    quarantine_file,
)


# =================================================
# Drag-and-drop scan area
# =================================================

class ScanDropZone(QFrame):
    """
    Accept a file or folder dropped by the user
    and send its local path to the main window.
    """

    path_dropped = Signal(str)


    def __init__(self):

        super().__init__()

        self.setObjectName(
            "scanDropZone"
        )

        self.setAcceptDrops(
            True
        )

        self.setMinimumHeight(
            92
        )

        layout = QVBoxLayout(
            self
        )

        layout.setContentsMargins(
            20,
            14,
            20,
            14,
        )

        layout.setSpacing(
            4
        )

        self.title_label = QLabel(
            "DROP A FILE OR FOLDER TO SCAN"
        )

        self.title_label.setObjectName(
            "dropZoneTitle"
        )

        self.title_label.setAlignment(
            Qt.AlignCenter
        )

        self.message_label = QLabel(
            "Drag an item from File Explorer "
            "and release it here"
        )

        self.message_label.setObjectName(
            "dropZoneMessage"
        )

        self.message_label.setAlignment(
            Qt.AlignCenter
        )

        layout.addWidget(
            self.title_label
        )

        layout.addWidget(
            self.message_label
        )


    def set_drag_active(
        self,
        active,
    ):

        self.setProperty(
            "dragActive",
            active,
        )

        self.style().unpolish(
            self
        )

        self.style().polish(
            self
        )

        self.update()


    def dragEnterEvent(
        self,
        event,
    ):

        mime_data = (
            event.mimeData()
        )

        if not mime_data.hasUrls():

            event.ignore()

            return

        local_paths = [
            url.toLocalFile()
            for url in mime_data.urls()
            if url.isLocalFile()
        ]

        if not local_paths:

            event.ignore()

            return

        self.set_drag_active(
            True
        )

        self.title_label.setText(
            "RELEASE TO START SCANNING"
        )

        self.message_label.setText(
            os.path.basename(
                local_paths[0]
            )
            or local_paths[0]
        )

        event.acceptProposedAction()


    def dragMoveEvent(
        self,
        event,
    ):

        if event.mimeData().hasUrls():

            event.acceptProposedAction()

        else:

            event.ignore()


    def dragLeaveEvent(
        self,
        event,
    ):

        self.reset_display()

        event.accept()


    def dropEvent(
        self,
        event,
    ):

        local_paths = [
            url.toLocalFile()
            for url in (
                event.mimeData().urls()
            )
            if url.isLocalFile()
        ]

        self.reset_display()

        if not local_paths:

            event.ignore()

            return

        self.path_dropped.emit(
            local_paths[0]
        )

        event.acceptProposedAction()


    def reset_display(self):

        self.set_drag_active(
            False
        )

        self.title_label.setText(
            "DROP A FILE OR FOLDER TO SCAN"
        )

        self.message_label.setText(
            "Drag an item from File Explorer "
            "and release it here"
        )


# =================================================
# Main PegaShield window
# =================================================

class MainWindow(QWidget):
    """
    Main PegaShield security dashboard.
    """

    def __init__(self):

        super().__init__()

        self.worker = None

        self.quarantine_window = None

        self.clamav_directory = None

        self.clamscan_path = None

        self.freshclam_path = None

        self.clean_file_count = 0

        self.threat_count = 0

        initialize_application_data()

        self.setWindowTitle(
            "PegaShield"
        )

        self.setMinimumSize(
            1050,
            760,
        )

        self.resize(
            1250,
            900,
        )

        self.build_interface()

        self.detect_clamav()

        self.update_quarantine_count()


    # =============================================
    # Interface
    # =============================================

    def build_interface(self):

        main_layout = QVBoxLayout(
            self
        )

        main_layout.setContentsMargins(
            24,
            20,
            24,
            20,
        )

        main_layout.setSpacing(
            16
        )

        main_layout.addWidget(
            self.create_header()
        )

        main_layout.addWidget(
            self.create_security_banner()
        )

        main_layout.addLayout(
            self.create_status_cards()
        )

        main_layout.addWidget(
            self.create_action_panel()
        )

        self.scan_drop_zone = (
            ScanDropZone()
        )

        self.scan_drop_zone.path_dropped.connect(
            self.scan_dropped_path
        )

        main_layout.addWidget(
            self.scan_drop_zone
        )

        main_layout.addWidget(
            self.create_results_panel(),
            3,
        )

        main_layout.addWidget(
            self.create_log_panel(),
            2,
        )


    # =============================================
    # Header
    # =============================================

    def create_header(self):

        header = QFrame()

        header.setObjectName(
            "headerPanel"
        )

        layout = QHBoxLayout(
            header
        )

        layout.setContentsMargins(
            20,
            14,
            20,
            14,
        )

        brand_layout = QVBoxLayout()

        brand_layout.setSpacing(
            2
        )

        title = QLabel(
            "PEGASHIELD"
        )

        title.setObjectName(
            "brandTitle"
        )

        subtitle = QLabel(
            "Local threat detection powered "
            "by ClamAV"
        )

        subtitle.setObjectName(
            "brandSubtitle"
        )

        brand_layout.addWidget(
            title
        )

        brand_layout.addWidget(
            subtitle
        )

        self.operation_status_label = QLabel(
            "READY"
        )

        self.operation_status_label.setObjectName(
            "operationBadge"
        )

        self.operation_status_label.setAlignment(
            Qt.AlignCenter
        )

        layout.addLayout(
            brand_layout
        )

        layout.addStretch()

        layout.addWidget(
            self.operation_status_label
        )

        return header


    # =============================================
    # Security banner
    # =============================================

    def create_security_banner(self):

        self.security_banner = QFrame()

        self.security_banner.setObjectName(
            "securityBanner"
        )

        layout = QHBoxLayout(
            self.security_banner
        )

        layout.setContentsMargins(
            20,
            15,
            20,
            15,
        )

        text_layout = QVBoxLayout()

        text_layout.setSpacing(
            2
        )

        self.security_title_label = QLabel(
            "Checking protection status"
        )

        self.security_title_label.setObjectName(
            "securityTitle"
        )

        self.security_message_label = QLabel(
            "PegaShield is checking the "
            "ClamAV engine and signature "
            "database."
        )

        self.security_message_label.setObjectName(
            "securityMessage"
        )

        text_layout.addWidget(
            self.security_title_label
        )

        text_layout.addWidget(
            self.security_message_label
        )

        self.security_state_label = QLabel(
            "CHECKING"
        )

        self.security_state_label.setObjectName(
            "securityState"
        )

        self.security_state_label.setAlignment(
            Qt.AlignCenter
        )

        layout.addLayout(
            text_layout
        )

        layout.addStretch()

        layout.addWidget(
            self.security_state_label
        )

        return self.security_banner


    # =============================================
    # Status cards
    # =============================================

    def create_status_cards(self):

        cards_layout = QHBoxLayout()

        cards_layout.setSpacing(
            14
        )

        (
            engine_card,
            self.engine_status_label,
            self.version_label,
        ) = self.create_status_card(
            "CLAMAV ENGINE",
            "Checking...",
            "Detecting installation",
        )

        (
            database_card,
            self.database_label,
            self.database_detail_label,
        ) = self.create_status_card(
            "SIGNATURE DATABASE",
            "Checking...",
            "Verifying local database",
        )

        (
            quarantine_card,
            self.quarantine_count_label,
            self.quarantine_detail_label,
        ) = self.create_status_card(
            "QUARANTINE",
            "0 items",
            "Isolated threats",
        )

        cards_layout.addWidget(
            engine_card
        )

        cards_layout.addWidget(
            database_card
        )

        cards_layout.addWidget(
            quarantine_card
        )

        return cards_layout


    def create_status_card(
        self,
        heading,
        value,
        detail,
    ):

        card = QFrame()

        card.setObjectName(
            "statusCard"
        )

        layout = QVBoxLayout(
            card
        )

        layout.setContentsMargins(
            18,
            14,
            18,
            14,
        )

        layout.setSpacing(
            5
        )

        heading_label = QLabel(
            heading
        )

        heading_label.setObjectName(
            "cardHeading"
        )

        value_label = QLabel(
            value
        )

        value_label.setObjectName(
            "cardValue"
        )

        detail_label = QLabel(
            detail
        )

        detail_label.setObjectName(
            "cardDetail"
        )

        layout.addWidget(
            heading_label
        )

        layout.addWidget(
            value_label
        )

        layout.addWidget(
            detail_label
        )

        return (
            card,
            value_label,
            detail_label,
        )


    # =============================================
    # Action panel
    # =============================================

    def create_action_panel(self):

        panel = QFrame()

        panel.setObjectName(
            "sectionPanel"
        )

        panel_layout = QVBoxLayout(
            panel
        )

        panel_layout.setContentsMargins(
            18,
            15,
            18,
            15,
        )

        panel_layout.setSpacing(
            12
        )

        section_title = QLabel(
            "SECURITY ACTIONS"
        )

        section_title.setObjectName(
            "sectionTitle"
        )

        button_layout = QHBoxLayout()

        button_layout.setSpacing(
            10
        )

        self.scan_file_button = QPushButton(
            "Scan File"
        )

        self.scan_file_button.setObjectName(
            "primaryButton"
        )

        self.scan_folder_button = QPushButton(
            "Scan Folder"
        )

        self.scan_folder_button.setObjectName(
            "primaryButton"
        )

        self.update_button = QPushButton(
            "Update Database"
        )

        self.quarantine_selected_button = (
            QPushButton(
                "Quarantine Selected"
            )
        )

        self.open_quarantine_button = (
            QPushButton(
                "Open Quarantine"
            )
        )

        self.clear_results_button = QPushButton(
            "Clear Results"
        )

        button_layout.addWidget(
            self.scan_file_button
        )

        button_layout.addWidget(
            self.scan_folder_button
        )

        button_layout.addWidget(
            self.update_button
        )

        button_layout.addWidget(
            self.quarantine_selected_button
        )

        button_layout.addWidget(
            self.open_quarantine_button
        )

        button_layout.addWidget(
            self.clear_results_button
        )

        panel_layout.addWidget(
            section_title
        )

        panel_layout.addLayout(
            button_layout
        )

        self.update_button.clicked.connect(
            self.update_database
        )

        self.scan_file_button.clicked.connect(
            self.scan_file
        )

        self.scan_folder_button.clicked.connect(
            self.scan_folder
        )

        self.quarantine_selected_button.clicked.connect(
            self.quarantine_selected
        )

        self.open_quarantine_button.clicked.connect(
            self.open_quarantine
        )

        self.clear_results_button.clicked.connect(
            self.clear_results
        )

        return panel


    # =============================================
    # Results panel
    # =============================================

    def create_results_panel(self):

        panel = QFrame()

        panel.setObjectName(
            "sectionPanel"
        )

        panel_layout = QVBoxLayout(
            panel
        )

        panel_layout.setContentsMargins(
            18,
            15,
            18,
            15,
        )

        panel_layout.setSpacing(
            10
        )

        heading_layout = QHBoxLayout()

        section_title = QLabel(
            "SCAN RESULTS"
        )

        section_title.setObjectName(
            "sectionTitle"
        )

        self.summary_label = QLabel(
            "Scanned: 0   |   "
            "Clean: 0   |   "
            "Threats: 0"
        )

        self.summary_label.setObjectName(
            "summaryLabel"
        )

        heading_layout.addWidget(
            section_title
        )

        heading_layout.addStretch()

        heading_layout.addWidget(
            self.summary_label
        )

        self.results_table = QTableWidget()

        self.results_table.setColumnCount(
            3
        )

        self.results_table.setHorizontalHeaderLabels(
            [
                "File",
                "Status",
                "Threat",
            ]
        )

        header = (
            self.results_table
            .horizontalHeader()
        )

        header.setSectionResizeMode(
            0,
            QHeaderView.Stretch,
        )

        header.setSectionResizeMode(
            1,
            QHeaderView.ResizeToContents,
        )

        header.setSectionResizeMode(
            2,
            QHeaderView.Stretch,
        )

        self.results_table.setEditTriggers(
            QTableWidget.NoEditTriggers
        )

        self.results_table.setSelectionBehavior(
            QTableWidget.SelectRows
        )

        self.results_table.setSelectionMode(
            QTableWidget.SingleSelection
        )

        self.results_table.setAlternatingRowColors(
            True
        )

        panel_layout.addLayout(
            heading_layout
        )

        panel_layout.addWidget(
            self.results_table
        )

        return panel


    # =============================================
    # Log panel
    # =============================================

    def create_log_panel(self):

        panel = QFrame()

        panel.setObjectName(
            "sectionPanel"
        )

        layout = QVBoxLayout(
            panel
        )

        layout.setContentsMargins(
            18,
            15,
            18,
            15,
        )

        layout.setSpacing(
            10
        )

        title = QLabel(
            "ACTIVITY LOG"
        )

        title.setObjectName(
            "sectionTitle"
        )

        self.log_output = QTextEdit()

        self.log_output.setReadOnly(
            True
        )

        layout.addWidget(
            title
        )

        layout.addWidget(
            self.log_output
        )

        return panel


    # =============================================
    # Startup diagnostics
    # =============================================

    def detect_clamav(self):

        self.log_output.append(
            "PegaShield startup diagnostics..."
        )

        self.clamav_directory = (
            find_clamav_directory()
        )

        if not self.clamav_directory:

            self.engine_status_label.setText(
                "Not installed"
            )

            self.version_label.setText(
                "ClamAV installation required"
            )

            self.database_label.setText(
                "Unavailable"
            )

            self.database_detail_label.setText(
                "ClamAV engine not detected"
            )

            self.set_security_state(
                "Protection unavailable",
                (
                    "Install ClamAV before "
                    "using local threat "
                    "detection."
                ),
                "OFFLINE",
            )

            self.set_operation_status(
                "ACTION REQUIRED"
            )

            self.set_operation_buttons_enabled(
                False
            )

            self.log_output.append(
                "ERROR: ClamAV was not found."
            )

            return

        (
            self.clamscan_path,
            self.freshclam_path,
        ) = get_clamav_executable_paths(
            self.clamav_directory
        )

        version = get_clamav_version(
            self.clamscan_path
        )

        self.engine_status_label.setText(
            "Installed"
        )

        self.version_label.setText(
            version
        )

        if database_is_ready():

            self.database_label.setText(
                "Ready"
            )

            self.database_detail_label.setText(
                "Virus signatures available"
            )

            self.set_security_state(
                "Local protection is ready",
                (
                    "ClamAV is installed and "
                    "the local signature "
                    "database is available."
                ),
                "PROTECTED",
            )

        else:

            self.database_label.setText(
                "Update required"
            )

            self.database_detail_label.setText(
                "Virus signatures unavailable"
            )

            self.set_security_state(
                "Database update required",
                (
                    "Update the signature "
                    "database before scanning."
                ),
                "ATTENTION",
            )

        self.set_operation_status(
            "READY"
        )

        self.log_output.append(
            "ClamAV detected: "
            f"{self.clamav_directory}"
        )

        self.log_output.append(
            f"Engine: {version}"
        )

        self.log_output.append(
            "Database directory: "
            f"{DATABASE_DIRECTORY}"
        )

        self.log_output.append(
            "Startup diagnostics completed."
        )


    # =============================================
    # Dashboard state
    # =============================================

    def set_security_state(
        self,
        title,
        message,
        state,
    ):

        self.security_title_label.setText(
            title
        )

        self.security_message_label.setText(
            message
        )

        self.security_state_label.setText(
            state
        )


    def set_operation_status(
        self,
        status,
    ):

        self.operation_status_label.setText(
            status
        )


    # =============================================
    # Background commands
    # =============================================

    def set_operation_buttons_enabled(
        self,
        enabled,
    ):

        self.update_button.setEnabled(
            enabled
        )

        self.scan_file_button.setEnabled(
            enabled
        )

        self.scan_folder_button.setEnabled(
            enabled
        )

        self.scan_drop_zone.setEnabled(
            enabled
        )


    def start_command(
        self,
        command,
        status,
        operation_type,
    ):

        if (
            self.worker is not None
            and self.worker.isRunning()
        ):

            QMessageBox.information(
                self,
                "Operation in Progress",
                (
                    "Wait for the current "
                    "operation to finish."
                ),
            )

            return

        self.set_operation_buttons_enabled(
            False
        )

        self.set_operation_status(
            status
        )

        self.worker = CommandWorker(
            command,
            operation_type,
        )

        self.worker.log_signal.connect(
            self.append_log
        )

        self.worker.scan_result_signal.connect(
            self.add_scan_result
        )

        self.worker.operation_finished.connect(
            self.command_finished
        )

        self.worker.start()


    # =============================================
    # Database update
    # =============================================

    def update_database(self):

        self.log_output.append(
            "\nStarting database update..."
        )

        command = [
            self.freshclam_path,
            "--config-file",
            FRESHCLAM_CONFIG_PATH,
        ]

        self.start_command(
            command,
            "UPDATING",
            "update",
        )


    # =============================================
    # Scan operations
    # =============================================

    def prepare_new_scan(self):

        self.results_table.setRowCount(
            0
        )

        self.clean_file_count = 0

        self.threat_count = 0

        self.update_summary()


    def start_scan_path(
        self,
        path,
    ):

        if not os.path.exists(
            path
        ):

            QMessageBox.warning(
                self,
                "Item Not Found",
                (
                    "The selected file or "
                    "folder no longer exists."
                ),
            )

            return

        self.prepare_new_scan()

        if os.path.isdir(
            path
        ):

            self.log_output.append(
                "\nStarting folder scan: "
                f"{path}"
            )

            command = [
                self.clamscan_path,
                "--recursive",
                "--database",
                DATABASE_DIRECTORY,
                path,
            ]

            status = "SCANNING FOLDER"

        else:

            self.log_output.append(
                "\nStarting file scan: "
                f"{path}"
            )

            command = [
                self.clamscan_path,
                "--database",
                DATABASE_DIRECTORY,
                path,
            ]

            status = "SCANNING FILE"

        self.start_command(
            command,
            status,
            "scan",
        )


    def scan_file(self):

        file_path, _ = (
            QFileDialog.getOpenFileName(
                self,
                "Select File to Scan",
            )
        )

        if file_path:

            self.start_scan_path(
                file_path
            )


    def scan_folder(self):

        folder_path = (
            QFileDialog.getExistingDirectory(
                self,
                "Select Folder to Scan",
            )
        )

        if folder_path:

            self.start_scan_path(
                folder_path
            )


    def scan_dropped_path(
        self,
        path,
    ):

        if (
            self.worker is not None
            and self.worker.isRunning()
        ):

            QMessageBox.information(
                self,
                "Operation in Progress",
                (
                    "Wait for the current "
                    "operation to finish before "
                    "starting another scan."
                ),
            )

            return

        self.log_output.append(
            "\nItem received by drag and drop:"
        )

        self.log_output.append(
            path
        )

        self.start_scan_path(
            path
        )


    # =============================================
    # Scan results
    # =============================================

    def add_scan_result(
        self,
        file_path,
        status,
        threat_name,
    ):

        row = (
            self.results_table.rowCount()
        )

        self.results_table.insertRow(
            row
        )

        self.results_table.setItem(
            row,
            0,
            QTableWidgetItem(
                file_path
            ),
        )

        self.results_table.setItem(
            row,
            1,
            QTableWidgetItem(
                status
            ),
        )

        self.results_table.setItem(
            row,
            2,
            QTableWidgetItem(
                threat_name
            ),
        )

        if status == "Clean":

            self.clean_file_count += 1

        elif status == "Threat detected":

            self.threat_count += 1

            self.set_security_state(
                "Threat detected",
                (
                    "PegaShield detected a "
                    "potentially unsafe file. "
                    "Review the scan results."
                ),
                "THREAT",
            )

        self.update_summary()


    def update_summary(self):

        total = (
            self.clean_file_count
            + self.threat_count
        )

        self.summary_label.setText(
            f"Scanned: {total}   |   "
            f"Clean: {self.clean_file_count}"
            "   |   "
            f"Threats: {self.threat_count}"
        )


    def clear_results(self):

        self.results_table.setRowCount(
            0
        )

        self.clean_file_count = 0

        self.threat_count = 0

        self.update_summary()


    # =============================================
    # Quarantine
    # =============================================

    def quarantine_selected(self):

        row = (
            self.results_table.currentRow()
        )

        if row < 0:

            QMessageBox.information(
                self,
                "No Selection",
                (
                    "Select a detected threat "
                    "from the results table."
                ),
            )

            return

        file_item = (
            self.results_table.item(
                row,
                0,
            )
        )

        status_item = (
            self.results_table.item(
                row,
                1,
            )
        )

        threat_item = (
            self.results_table.item(
                row,
                2,
            )
        )

        if (
            not file_item
            or not status_item
        ):

            return

        file_path = (
            file_item.text()
        )

        status = (
            status_item.text()
        )

        threat_name = (
            threat_item.text()
            if threat_item
            else ""
        )

        if (
            status
            != "Threat detected"
        ):

            QMessageBox.information(
                self,
                "File Not Eligible",
                (
                    "Only detected threats "
                    "can be quarantined."
                ),
            )

            return

        if not os.path.isfile(
            file_path
        ):

            QMessageBox.warning(
                self,
                "File Missing",
                (
                    "The detected file no "
                    "longer exists at:\n\n"
                    f"{file_path}"
                ),
            )

            return

        confirmation = (
            QMessageBox.warning(
                self,
                "Quarantine Threat",
                (
                    "Move this detected file "
                    "to quarantine?\n\n"
                    f"Threat: {threat_name}"
                    "\n\n"
                    f"File: {file_path}"
                ),
                (
                    QMessageBox.Yes
                    | QMessageBox.No
                ),
                QMessageBox.Yes,
            )
        )

        if (
            confirmation
            != QMessageBox.Yes
        ):

            return

        try:

            quarantine_file(
                file_path,
                threat_name,
            )

            status_item.setText(
                "Quarantined"
            )

            self.set_operation_status(
                "QUARANTINED"
            )

            self.set_security_state(
                "Threat isolated",
                (
                    "The detected file was "
                    "moved into PegaShield "
                    "quarantine."
                ),
                "SECURED",
            )

            self.log_output.append(
                "\nThreat quarantined:"
            )

            self.log_output.append(
                file_path
            )

            self.update_quarantine_count()

            QMessageBox.information(
                self,
                "Threat Quarantined",
                (
                    "The detected file was "
                    "moved to quarantine."
                ),
            )

        except Exception as error:

            QMessageBox.critical(
                self,
                "Quarantine Failed",
                str(error),
            )


    def update_quarantine_count(self):

        records = (
            load_quarantine_records()
        )

        count = len(
            records
        )

        self.quarantine_count_label.setText(
            f"{count} items"
        )

        if count == 1:

            self.quarantine_detail_label.setText(
                "1 isolated threat"
            )

        else:

            self.quarantine_detail_label.setText(
                f"{count} isolated threats"
            )


    def open_quarantine(self):

        if (
            self.quarantine_window
            is None
        ):

            self.quarantine_window = (
                QuarantineWindow()
            )

            self.quarantine_window.quarantine_changed.connect(
                self.update_quarantine_count
            )

        self.quarantine_window.refresh_table()

        self.quarantine_window.show()

        self.quarantine_window.raise_()

        self.quarantine_window.activateWindow()


    # =============================================
    # Worker output
    # =============================================

    def append_log(
        self,
        text,
    ):

        self.log_output.append(
            text
        )


    def command_finished(
        self,
        return_code,
    ):

        self.set_operation_buttons_enabled(
            True
        )

        if return_code == 0:

            self.set_operation_status(
                "READY"
            )

            if database_is_ready():

                self.database_label.setText(
                    "Ready"
                )

                self.database_detail_label.setText(
                    "Virus signatures available"
                )

                if self.threat_count == 0:

                    self.set_security_state(
                        "Local protection is ready",
                        (
                            "ClamAV is installed "
                            "and the local "
                            "signature database "
                            "is available."
                        ),
                        "PROTECTED",
                    )

        elif return_code == 1:

            self.set_operation_status(
                "THREAT DETECTED"
            )

            self.set_security_state(
                "Threat detected",
                (
                    "Review the scan results "
                    "and quarantine the "
                    "detected file."
                ),
                "THREAT",
            )

        else:

            self.set_operation_status(
                "FAILED"
            )

            self.set_security_state(
                "Operation failed",
                (
                    "Review the activity log "
                    "for details."
                ),
                "ERROR",
            )