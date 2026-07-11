PEGASHIELD_STYLESHEET = """

/* =================================================
   Global application
   ================================================= */

QWidget {
    background-color: #08111F;
    color: #E6EDF7;

    font-family: "Segoe UI";
    font-size: 10pt;
}


/* =================================================
   Main PegaShield header
   ================================================= */

QFrame#headerPanel {
    background-color: #0D192B;

    border: 1px solid #20324A;
    border-radius: 14px;
}


QLabel#brandTitle {
    background-color: transparent;

    color: #F8FAFC;

    font-size: 22pt;
    font-weight: 800;

    letter-spacing: 2px;
}


QLabel#brandSubtitle {
    background-color: transparent;

    color: #8FA4BF;

    font-size: 9pt;
}


QLabel#operationBadge {
    min-width: 120px;
    min-height: 34px;

    padding-left: 14px;
    padding-right: 14px;

    background-color: #102D27;

    color: #62E6B5;

    border: 1px solid #1D6654;
    border-radius: 17px;

    font-size: 9pt;
    font-weight: 700;
}


/* =================================================
   Security status banner
   ================================================= */

QFrame#securityBanner {
    background-color: #0B2430;

    border: 1px solid #175168;
    border-radius: 14px;
}


QLabel#securityTitle {
    background-color: transparent;

    color: #F2FAFF;

    font-size: 15pt;
    font-weight: 700;
}


QLabel#securityMessage {
    background-color: transparent;

    color: #9CB3C8;

    font-size: 9pt;
}


QLabel#securityState {
    min-width: 120px;
    min-height: 38px;

    padding-left: 16px;
    padding-right: 16px;

    background-color: #123B35;

    color: #72F0C2;

    border: 1px solid #267C69;
    border-radius: 19px;

    font-size: 9pt;
    font-weight: 800;
}


/* =================================================
   Dashboard status cards
   ================================================= */

QFrame#statusCard {
    min-height: 90px;

    background-color: #0D192B;

    border: 1px solid #20324A;
    border-radius: 13px;
}


QFrame#statusCard:hover {
    background-color: #101E32;

    border-color: #315176;
}


QLabel#cardHeading {
    background-color: transparent;

    color: #7890AE;

    font-size: 8pt;
    font-weight: 700;

    letter-spacing: 1px;
}


QLabel#cardValue {
    background-color: transparent;

    color: #F8FAFC;

    font-size: 16pt;
    font-weight: 700;
}


QLabel#cardDetail {
    background-color: transparent;

    color: #91A4BC;

    font-size: 9pt;
}


/* =================================================
   Dashboard sections
   ================================================= */

QFrame#sectionPanel {
    background-color: #0D192B;

    border: 1px solid #20324A;
    border-radius: 13px;
}


QLabel#sectionTitle {
    background-color: transparent;

    color: #A9BBD0;

    font-size: 9pt;
    font-weight: 800;

    letter-spacing: 1px;
}


QLabel#summaryLabel {
    background-color: transparent;

    color: #8FA4BF;

    font-size: 9pt;
    font-weight: 600;
}


/* =================================================
   General labels
   ================================================= */

QLabel {
    background-color: transparent;

    color: #E6EDF7;
}


/* =================================================
   Standard buttons
   ================================================= */

QPushButton {
    min-height: 40px;

    padding-left: 16px;
    padding-right: 16px;

    background-color: #14233A;

    color: #EAF1FA;

    border: 1px solid #2A405E;
    border-radius: 9px;

    font-weight: 600;
}


QPushButton:hover {
    background-color: #1B304D;

    border-color: #4774A9;

    color: #FFFFFF;
}


QPushButton:pressed {
    background-color: #0E1B2E;

    border-color: #315E92;
}


QPushButton:disabled {
    background-color: #0C1625;

    color: #53667D;

    border-color: #17263A;
}


/* =================================================
   Primary scan buttons
   ================================================= */

QPushButton#primaryButton {
    background-color: #1769E0;

    color: #FFFFFF;

    border: 1px solid #3384F4;

    font-weight: 700;
}


QPushButton#primaryButton:hover {
    background-color: #2379F0;

    border-color: #67A6FF;
}


QPushButton#primaryButton:pressed {
    background-color: #1056BC;

    border-color: #2379F0;
}


QPushButton#primaryButton:disabled {
    background-color: #183457;

    color: #6685A9;

    border-color: #254465;
}


/* =================================================
   Tables
   ================================================= */

QTableWidget {
    background-color: #091423;

    alternate-background-color: #0C192A;

    color: #DCE7F5;

    border: 1px solid #1D3048;
    border-radius: 9px;

    gridline-color: #17283D;

    selection-background-color: #175FC4;
    selection-color: #FFFFFF;

    outline: none;
}


QTableWidget::item {
    min-height: 28px;

    padding: 7px;

    border: none;
}


QTableWidget::item:hover {
    background-color: #12243A;
}


QTableWidget::item:selected {
    background-color: #175FC4;

    color: #FFFFFF;
}


QHeaderView {
    background-color: transparent;
}


QHeaderView::section {
    min-height: 36px;

    padding: 7px;

    background-color: #111F33;

    color: #9EB1C9;

    border: none;

    border-right: 1px solid #20324A;
    border-bottom: 1px solid #20324A;

    font-size: 9pt;
    font-weight: 700;
}


/* =================================================
   Activity log
   ================================================= */

QTextEdit {
    background-color: #050B14;

    color: #9DE8C8;

    border: 1px solid #1D3048;
    border-radius: 9px;

    padding: 10px;

    font-family: "Cascadia Mono", "Consolas";
    font-size: 9pt;

    selection-background-color: #175FC4;
    selection-color: #FFFFFF;
}


/* =================================================
   Scroll bars
   ================================================= */

QScrollBar:vertical {
    width: 11px;

    background-color: #08111F;

    border: none;

    margin: 2px;
}


QScrollBar::handle:vertical {
    min-height: 30px;

    background-color: #2A3D57;

    border-radius: 5px;
}


QScrollBar::handle:vertical:hover {
    background-color: #405C7D;
}


QScrollBar::add-line:vertical,
QScrollBar::sub-line:vertical {
    height: 0;
}


QScrollBar::add-page:vertical,
QScrollBar::sub-page:vertical {
    background: none;
}


QScrollBar:horizontal {
    height: 11px;

    background-color: #08111F;

    border: none;

    margin: 2px;
}


QScrollBar::handle:horizontal {
    min-width: 30px;

    background-color: #2A3D57;

    border-radius: 5px;
}


QScrollBar::handle:horizontal:hover {
    background-color: #405C7D;
}


QScrollBar::add-line:horizontal,
QScrollBar::sub-line:horizontal {
    width: 0;
}


QScrollBar::add-page:horizontal,
QScrollBar::sub-page:horizontal {
    background: none;
}


/* =================================================
   Message boxes
   ================================================= */

QMessageBox {
    background-color: #0D192B;
}


QMessageBox QLabel {
    color: #E6EDF7;

    min-width: 300px;
}


QMessageBox QPushButton {
    min-width: 90px;
}


/* =================================================
   Tooltips
   ================================================= */

QToolTip {
    padding: 7px;

    background-color: #14233A;

    color: #F8FAFC;

    border: 1px solid #385777;
    border-radius: 5px;
}
/* =================================================
   Drag-and-drop scan area
   ================================================= */

QFrame#scanDropZone {
    min-height: 90px;

    background-color: #0A1728;

    border: 2px dashed #315C8A;
    border-radius: 13px;
}


QFrame#scanDropZone:hover {
    background-color: #0D1E33;

    border-color: #4C8FD8;
}


QFrame#scanDropZone[dragActive="true"] {
    background-color: #102A46;

    border: 2px solid #4EA1FF;
}


QFrame#scanDropZone:disabled {
    background-color: #09111D;

    border-color: #1D3048;
}


QLabel#dropZoneTitle {
    background-color: transparent;

    color: #A8D4FF;

    font-size: 10pt;
    font-weight: 800;

    letter-spacing: 1px;
}


QLabel#dropZoneMessage {
    background-color: transparent;

    color: #7890AE;

    font-size: 9pt;
}

"""