PEGASHIELD_STYLESHEET = """
/* =================================================
   Global application
   ================================================= */

QWidget {
    background-color: #0B1220;
    color: #E5E7EB;
    font-family: "Segoe UI";
    font-size: 10pt;
}


/* =================================================
   Labels
   ================================================= */

QLabel {
    background-color: transparent;
    color: #E5E7EB;
}


/* =================================================
   Buttons
   ================================================= */

QPushButton {
    min-height: 38px;
    padding: 0 16px;

    background-color: #172033;
    color: #F8FAFC;

    border: 1px solid #2B3850;
    border-radius: 8px;

    font-weight: 600;
}

QPushButton:hover {
    background-color: #21304A;
    border-color: #4B6B9A;
}

QPushButton:pressed {
    background-color: #111827;
}

QPushButton:disabled {
    background-color: #111827;
    color: #64748B;
    border-color: #1F2937;
}


/* =================================================
   Tables
   ================================================= */

QTableWidget {
    background-color: #111827;
    alternate-background-color: #152033;

    color: #E5E7EB;

    border: 1px solid #263449;
    border-radius: 8px;

    gridline-color: #263449;

    selection-background-color: #1D4ED8;
    selection-color: #FFFFFF;

    outline: none;
}

QTableWidget::item {
    padding: 8px;
    border: none;
}

QTableWidget::item:selected {
    background-color: #1D4ED8;
    color: #FFFFFF;
}

QHeaderView::section {
    min-height: 34px;

    background-color: #172033;
    color: #CBD5E1;

    border: none;
    border-right: 1px solid #263449;
    border-bottom: 1px solid #263449;

    padding: 7px;

    font-weight: 600;
}


/* =================================================
   Log output
   ================================================= */

QTextEdit {
    background-color: #070D18;
    color: #A7F3D0;

    border: 1px solid #263449;
    border-radius: 8px;

    padding: 10px;

    font-family: "Cascadia Mono", "Consolas";
    font-size: 9pt;

    selection-background-color: #1D4ED8;
}


/* =================================================
   Scroll bars
   ================================================= */

QScrollBar:vertical {
    width: 12px;

    background-color: #0B1220;

    border: none;
    margin: 0;
}

QScrollBar::handle:vertical {
    min-height: 30px;

    background-color: #334155;

    border-radius: 6px;
}

QScrollBar::handle:vertical:hover {
    background-color: #475569;
}

QScrollBar::add-line:vertical,
QScrollBar::sub-line:vertical {
    height: 0;
}

QScrollBar:horizontal {
    height: 12px;

    background-color: #0B1220;

    border: none;
    margin: 0;
}

QScrollBar::handle:horizontal {
    min-width: 30px;

    background-color: #334155;

    border-radius: 6px;
}

QScrollBar::handle:horizontal:hover {
    background-color: #475569;
}

QScrollBar::add-line:horizontal,
QScrollBar::sub-line:horizontal {
    width: 0;
}


/* =================================================
   Tooltips
   ================================================= */

QToolTip {
    background-color: #172033;
    color: #F8FAFC;

    border: 1px solid #334155;

    padding: 6px;
}
"""