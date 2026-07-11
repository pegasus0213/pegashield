from PySide6.QtCore import (
    Qt,
)

from PySide6.QtWidgets import (
    QAbstractItemView,
    QFrame,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from app.services.scan_history import (
    clear_scan_history,
    load_scan_history,
)


# =================================================
# Scan-history window
# =================================================

class HistoryWindow(QWidget):
    """
    Display scans saved by PegaShield.
    """

    def __init__(self):

        super().__init__()

        self.setWindowTitle(
            "PegaShield - Scan History"
        )

        self.setMinimumSize(
            900,
            520,
        )

        self.resize(
            1100,
            620,
        )

        self.build_interface()

        self.refresh_table()


    def build_interface(
        self,
    ):

        main_layout = QVBoxLayout(
            self
        )

        main_layout.setContentsMargins(
            18,
            18,
            18,
            18,
        )

        main_layout.setSpacing(
            12
        )

        header = QFrame()

        header.setObjectName(
            "headerPanel"
        )

        header_layout = QHBoxLayout(
            header
        )

        header_layout.setContentsMargins(
            18,
            14,
            18,
            14,
        )

        title_layout = QVBoxLayout()

        title = QLabel(
            "SCAN HISTORY"
        )

        title.setObjectName(
            "brandTitle"
        )

        subtitle = QLabel(
            "Previous PegaShield scan summaries"
        )

        subtitle.setObjectName(
            "brandSubtitle"
        )

        title_layout.addWidget(
            title
        )

        title_layout.addWidget(
            subtitle
        )

        self.record_count_label = QLabel(
            "0 scans"
        )

        self.record_count_label.setObjectName(
            "operationBadge"
        )

        self.record_count_label.setAlignment(
            Qt.AlignCenter
        )

        header_layout.addLayout(
            title_layout
        )

        header_layout.addStretch()

        header_layout.addWidget(
            self.record_count_label
        )

        main_layout.addWidget(
            header
        )

        self.history_table = QTableWidget()

        self.history_table.setColumnCount(
            7
        )

        self.history_table.setHorizontalHeaderLabels(
            [
                "Date",
                "Type",
                "Target",
                "Clean",
                "Threats",
                "Result",
                "Total",
            ]
        )

        self.history_table.setEditTriggers(
            QAbstractItemView.NoEditTriggers
        )

        self.history_table.setSelectionBehavior(
            QAbstractItemView.SelectRows
        )

        self.history_table.setSelectionMode(
            QAbstractItemView.SingleSelection
        )

        self.history_table.setAlternatingRowColors(
            True
        )

        self.history_table.setSortingEnabled(
            False
        )

        header_view = (
            self.history_table
            .horizontalHeader()
        )

        header_view.setSectionResizeMode(
            0,
            QHeaderView.ResizeToContents,
        )

        header_view.setSectionResizeMode(
            1,
            QHeaderView.ResizeToContents,
        )

        header_view.setSectionResizeMode(
            2,
            QHeaderView.Stretch,
        )

        header_view.setSectionResizeMode(
            3,
            QHeaderView.ResizeToContents,
        )

        header_view.setSectionResizeMode(
            4,
            QHeaderView.ResizeToContents,
        )

        header_view.setSectionResizeMode(
            5,
            QHeaderView.ResizeToContents,
        )

        header_view.setSectionResizeMode(
            6,
            QHeaderView.ResizeToContents,
        )

        main_layout.addWidget(
            self.history_table
        )

        button_layout = QHBoxLayout()

        button_layout.addStretch()

        self.refresh_button = QPushButton(
            "Refresh"
        )

        self.clear_button = QPushButton(
            "Clear History"
        )

        self.clear_button.setObjectName(
            "dangerButton"
        )

        self.close_button = QPushButton(
            "Close"
        )

        button_layout.addWidget(
            self.refresh_button
        )

        button_layout.addWidget(
            self.clear_button
        )

        button_layout.addWidget(
            self.close_button
        )

        main_layout.addLayout(
            button_layout
        )

        self.refresh_button.clicked.connect(
            self.refresh_table
        )

        self.clear_button.clicked.connect(
            self.clear_history
        )

        self.close_button.clicked.connect(
            self.close
        )


    def refresh_table(
        self,
    ):

        records = load_scan_history()

        self.history_table.setRowCount(
            0
        )

        for record in records:

            row = (
                self.history_table
                .rowCount()
            )

            self.history_table.insertRow(
                row
            )

            clean_count = int(
                record.get(
                    "clean_count",
                    0,
                )
            )

            threat_count = int(
                record.get(
                    "threat_count",
                    0,
                )
            )

            total_count = (
                clean_count
                + threat_count
            )

            values = [
                record.get(
                    "date",
                    "",
                ),
                record.get(
                    "scan_type",
                    "",
                ),
                record.get(
                    "target",
                    "",
                ),
                str(
                    clean_count
                ),
                str(
                    threat_count
                ),
                record.get(
                    "result",
                    "",
                ),
                str(
                    total_count
                ),
            ]

            for column, value in enumerate(
                values
            ):

                item = QTableWidgetItem(
                    value
                )

                if column in (
                    3,
                    4,
                    6,
                ):

                    item.setTextAlignment(
                        Qt.AlignCenter
                    )

                self.history_table.setItem(
                    row,
                    column,
                    item,
                )

        count = len(
            records
        )

        if count == 1:

            count_text = "1 scan"

        else:

            count_text = (
                f"{count} scans"
            )

        self.record_count_label.setText(
            count_text
        )


    def clear_history(
        self,
    ):

        if (
            self.history_table.rowCount()
            == 0
        ):

            QMessageBox.information(
                self,
                "Scan History",
                "There is no scan history to clear.",
            )

            return

        confirmation = QMessageBox.warning(
            self,
            "Clear Scan History",
            (
                "Delete all saved scan-history "
                "records?\n\n"
                "This action cannot be undone."
            ),
            (
                QMessageBox.Yes
                | QMessageBox.No
            ),
            QMessageBox.No,
        )

        if (
            confirmation
            != QMessageBox.Yes
        ):

            return

        try:

            clear_scan_history()

            self.refresh_table()

        except OSError as error:

            QMessageBox.critical(
                self,
                "History Error",
                (
                    "PegaShield could not clear "
                    "the scan history.\n\n"
                    f"{error}"
                ),
            )