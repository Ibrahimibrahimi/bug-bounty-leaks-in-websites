import sys
import uuid
import threading
import requests

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
    QLabel, QPushButton, QScrollArea, QTextEdit, QFrame, QSizePolicy
)
from PyQt5.QtCore import (
    Qt, QThread, pyqtSignal, QTimer, QPropertyAnimation,
    QEasingCurve, QSize, pyqtProperty, QPoint
)
from PyQt5.QtGui import (
    QColor, QPainter, QPainterPath, QFont, QFontMetrics,
    QLinearGradient, QPen, QBrush, QIcon, QPixmap, QPalette
)


# ─────────────────────────────────────────────
#  Backend
# ─────────────────────────────────────────────

def clean(text: str, replacements: dict) -> str:
    for old, new in replacements.items():
        text = text.replace(old, new)
    return text


def getModelAnswer(query: str = "hi", randomiseToken: bool = False) -> str:
    url = "https://talkai.info/chat/send/"
    MODEL_OUTPUT = "event: trylimit 29An internal server error occurred."
    random_uuid = uuid.uuid4()
    replacements = {
        "\ndata:": "", "\n": "", MODEL_OUTPUT: "",
        "event": "\n", "trylimit": "\n\n  + trylimit :",
        "An internal server error occurred.": "",
        ": botmodel GPT 4.1 nano ": ""
    }
    TOKEN_TEXT = ("front=983159c1a0d70d635ba222039dfcf1ebb28830de2fe603511ad03b282cd997faa"
                  "%3A2%3A%7Bi%3A0%3Bs%3A11%3A%22_csrf-front%22%3Bi%3A1%3Bs%3A32%3A"
                  "%22i27T4lOZk9kL6-A3jXGqZyvitsv5E5V2%22%3B%7D")
    TOKEN = random_uuid if randomiseToken else TOKEN_TEXT
    CSRF_TOKEN = ("983159c1a0d70d635ba222039dfcf1ebb28830de2fe603511ad03b282cd997faa"
                  "%3A2%3A%7Bi%3A0%3Bs%3A11%3A%22_csrf-front%22%3Bi%3A1%3Bs%3A32%3A"
                  "%22i27T4lOZk9kL6-A3jXGqZyvitsv5E5V2%22%3B%7D")
    headers = {
        "Host": "talkai.info",
        "User-Agent": "Mozilla/5.0 (Windows NT 6.3; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
        "Accept": "application/json, text/event-stream",
        "Accept-Language": "en-US,en;q=0.5",
        "Referer": "https://talkai.info/chat/",
        "Content-Type": "application/json",
        "Origin": "https://talkai.info",
        "Connection": "keep-alive"
    }
    cookies = {"talkai-front": TOKEN, "_csrf-front": CSRF_TOKEN}
    payload = {
        "type": "chat",
        "messagesHistory": [{
            "id": "11c594c7-ef6a-4bd3-b551-a0fb4f3b781e",
            "from": "you", "content": query, "model": "gpt-4.1-nano"
        }],
        "settings": {"model": "gpt-4.1-nano", "temperature": 0.7}
    }
    response = requests.post(url, headers=headers, cookies=cookies, json=payload)
    return clean(response.text, replacements)


# ─────────────────────────────────────────────
#  Worker Thread
# ─────────────────────────────────────────────

class AIWorker(QThread):
    response_ready = pyqtSignal(str)

    def __init__(self, query: str, randomise_token: bool = False):
        super().__init__()
        self.query = query
        self.randomise_token = randomise_token

    def run(self):
        try:
            answer = getModelAnswer(self.query, self.randomise_token)
            self.response_ready.emit(answer.strip() or "(empty response)")
        except Exception as e:
            self.response_ready.emit(f"[Error] {e}")


# ─────────────────────────────────────────────
#  Color Palette
# ─────────────────────────────────────────────

C = {
    "bg":        "#0D0F1E",
    "panel":     "#151727",
    "surface":   "#1C1F35",
    "border":    "#252840",
    "accent":    "#5B6AF0",
    "accent2":   "#8F9BFF",
    "user_bg":   "#5B6AF0",
    "bot_bg":    "#1C1F35",
    "text":      "#E2E6FF",
    "dim":       "#6B7280",
    "green":     "#4ADE80",
    "input_bg":  "#181B2E",
}


# ─────────────────────────────────────────────
#  Typing Dots Widget
# ─────────────────────────────────────────────

class TypingDots(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setFixedSize(56, 28)
        self._phase = 0.0
        self._timer = QTimer(self)
        self._timer.timeout.connect(self._tick)
        self._timer.start(60)

    def _tick(self):
        self._phase += 0.25
        self.update()

    def paintEvent(self, e):
        import math
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        r = 5
        gap = 14
        x = 8
        y = self.height() // 2
        for i in range(3):
            alpha = 0.3 + 0.7 * (0.5 + 0.5 * math.sin(self._phase + i * 1.2))
            col = QColor(C["accent"])
            col.setAlphaF(alpha)
            p.setBrush(QBrush(col))
            p.setPen(Qt.NoPen)
            p.drawEllipse(x, y - r, r * 2, r * 2)
            x += r * 2 + gap

    def stop(self):
        self._timer.stop()


# ─────────────────────────────────────────────
#  Chat Bubble
# ─────────────────────────────────────────────

class ChatBubble(QWidget):
    MAX_W = 380
    PAD_X = 18
    PAD_Y = 12
    RADIUS = 18

    def __init__(self, text: str, is_user: bool, parent=None):
        super().__init__(parent)
        self.text = text
        self.is_user = is_user
        self._bg = QColor(C["user_bg"] if is_user else C["bot_bg"])
        self._fg = QColor(C["text"])
        self._setup()

    def _setup(self):
        font = QFont("Segoe UI", 10)
        fm = QFontMetrics(font)
        # Compute wrapped size
        flags = Qt.TextWordWrap | Qt.AlignLeft
        rect = fm.boundingRect(0, 0, self.MAX_W, 10000, flags, self.text)
        w = min(rect.width(), self.MAX_W) + self.PAD_X * 2
        h = rect.height() + self.PAD_Y * 2
        self.setFixedSize(w, h)

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)

        # Shadow
        shadow = QColor(0, 0, 0, 60)
        p.setBrush(QBrush(shadow))
        p.setPen(Qt.NoPen)
        path_s = QPainterPath()
        path_s.addRoundedRect(2, 4, self.width()-2, self.height()-4, self.RADIUS, self.RADIUS)
        p.drawPath(path_s)

        # Bubble
        p.setBrush(QBrush(self._bg))
        path = QPainterPath()
        path.addRoundedRect(0, 0, self.width(), self.height()-4, self.RADIUS, self.RADIUS)
        p.drawPath(path)

        # Text
        p.setPen(QPen(self._fg))
        p.setFont(QFont("Segoe UI", 10))
        p.drawText(
            self.PAD_X, self.PAD_Y,
            self.width() - self.PAD_X * 2,
            self.height() - self.PAD_Y * 2,
            Qt.TextWordWrap | Qt.AlignLeft,
            self.text
        )


# ─────────────────────────────────────────────
#  Avatar
# ─────────────────────────────────────────────

class Avatar(QWidget):
    def __init__(self, label: str, is_user: bool, parent=None):
        super().__init__(parent)
        self.label = label
        self._bg = QColor(C["accent"] if is_user else C["surface"])
        self.setFixedSize(36, 36)

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        p.setBrush(QBrush(self._bg))
        p.setPen(Qt.NoPen)
        p.drawEllipse(0, 0, 36, 36)
        p.setPen(QPen(QColor(C["text"])))
        p.setFont(QFont("Segoe UI", 8, QFont.Bold))
        p.drawText(0, 0, 36, 36, Qt.AlignCenter, self.label)


# ─────────────────────────────────────────────
#  Message Row
# ─────────────────────────────────────────────

def make_message_row(text: str, is_user: bool) -> QWidget:
    row = QWidget()
    row.setStyleSheet("background: transparent;")
    layout = QHBoxLayout(row)
    layout.setContentsMargins(16, 4, 16, 4)
    layout.setSpacing(10)

    av = Avatar("You" if is_user else "AI", is_user)
    bubble = ChatBubble(text, is_user)

    if is_user:
        layout.addStretch()
        layout.addWidget(bubble)
        layout.addWidget(av, alignment=Qt.AlignTop)
    else:
        layout.addWidget(av, alignment=Qt.AlignTop)
        layout.addWidget(bubble)
        layout.addStretch()

    return row


def make_typing_row() -> tuple:
    row = QWidget()
    row.setStyleSheet("background: transparent;")
    layout = QHBoxLayout(row)
    layout.setContentsMargins(16, 4, 16, 4)
    layout.setSpacing(10)

    av = Avatar("AI", False)
    dots = TypingDots()

    layout.addWidget(av, alignment=Qt.AlignTop)
    layout.addWidget(dots, alignment=Qt.AlignVCenter)
    layout.addStretch()

    return row, dots


# ─────────────────────────────────────────────
#  Sidebar Button
# ─────────────────────────────────────────────

class SidebarButton(QPushButton):
    def __init__(self, text, accent=False, parent=None):
        super().__init__(text, parent)
        self.accent = accent
        self.setCursor(Qt.PointingHandCursor)
        self.setFont(QFont("Segoe UI", 9, QFont.Bold if accent else QFont.Normal))
        self.setFixedHeight(36)
        self._apply_style(False)
        self.installEventFilter(self)

    def _apply_style(self, hovered: bool):
        if self.accent:
            bg = C["accent2"] if hovered else C["accent"]
            self.setStyleSheet(f"""
                QPushButton {{
                    background: {bg}; color: white;
                    border: none; border-radius: 8px;
                    padding: 0 12px; text-align: left;
                }}
            """)
        else:
            bg = C["surface"] if hovered else "transparent"
            self.setStyleSheet(f"""
                QPushButton {{
                    background: {bg}; color: {C['text']};
                    border: none; border-radius: 6px;
                    padding: 0 10px; text-align: left;
                }}
            """)

    def eventFilter(self, obj, event):
        from PyQt5.QtCore import QEvent
        if obj is self:
            if event.type() == QEvent.Enter:
                self._apply_style(True)
            elif event.type() == QEvent.Leave:
                self._apply_style(False)
        return super().eventFilter(obj, event)


# ─────────────────────────────────────────────
#  Send Button
# ─────────────────────────────────────────────

class SendButton(QPushButton):
    def __init__(self, parent=None):
        super().__init__("↑", parent)
        self.setCursor(Qt.PointingHandCursor)
        self.setFixedSize(40, 40)
        self.setFont(QFont("Segoe UI", 14, QFont.Bold))
        self._hovered = False
        self.installEventFilter(self)
        self._update()

    def _update(self):
        bg = C["accent2"] if self._hovered else C["accent"]
        self.setStyleSheet(f"""
            QPushButton {{
                background: {bg}; color: white;
                border: none; border-radius: 20px;
            }}
        """)

    def eventFilter(self, obj, event):
        from PyQt5.QtCore import QEvent
        if obj is self:
            if event.type() == QEvent.Enter:
                self._hovered = True; self._update()
            elif event.type() == QEvent.Leave:
                self._hovered = False; self._update()
        return super().eventFilter(obj, event)


# ─────────────────────────────────────────────
#  Randomise Token Toggle Button
# ─────────────────────────────────────────────

class RandomiseButton(QPushButton):
    """Toggle button: off = dim outline, on = green filled."""

    OFF_BG     = "transparent"
    OFF_BORDER = "#252840"
    OFF_FG     = "#6B7280"
    ON_BG      = "#14532D"
    ON_BORDER  = "#4ADE80"
    ON_FG      = "#4ADE80"

    def __init__(self, parent=None):
        super().__init__("⚄  Randomize", parent)
        self._on = False
        self.setCursor(Qt.PointingHandCursor)
        self.setFont(QFont("Segoe UI", 9, QFont.Bold))
        self.setFixedHeight(30)
        self.setCheckable(True)
        self.toggled.connect(self._on_toggle)
        self._apply_style()

    def _on_toggle(self, checked: bool):
        self._on = checked
        self._apply_style()

    def _apply_style(self):
        if self._on:
            self.setStyleSheet(f"""
                QPushButton {{
                    background: {self.ON_BG};
                    color: {self.ON_FG};
                    border: 1px solid {self.ON_BORDER};
                    border-radius: 8px;
                    padding: 0 12px;
                }}
                QPushButton:hover {{
                    background: #166534;
                }}
            """)
        else:
            self.setStyleSheet(f"""
                QPushButton {{
                    background: {self.OFF_BG};
                    color: {self.OFF_FG};
                    border: 1px solid {self.OFF_BORDER};
                    border-radius: 8px;
                    padding: 0 12px;
                }}
                QPushButton:hover {{
                    color: {C['text']};
                    border-color: {C['accent']};
                }}
            """)

    @property
    def is_on(self) -> bool:
        return self._on


# ─────────────────────────────────────────────
#  Main Window
# ─────────────────────────────────────────────

class ChatWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NeuralChat")
        self.resize(960, 680)
        self.setMinimumSize(700, 500)
        self._worker = None
        self._typing_row = None
        self._typing_dots = None
        self._randomise_token = False
        self._setup_ui()

    def _setup_ui(self):
        root = QWidget()
        root.setStyleSheet(f"background: {C['bg']};")
        self.setCentralWidget(root)

        layout = QHBoxLayout(root)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        layout.addWidget(self._build_sidebar())
        layout.addWidget(self._build_main(), stretch=1)

    # ── Sidebar ───────────────────────────────

    def _build_sidebar(self):
        sb = QWidget()
        sb.setFixedWidth(220)
        sb.setStyleSheet(f"background: {C['panel']}; border-right: 1px solid {C['border']};")

        layout = QVBoxLayout(sb)
        layout.setContentsMargins(14, 24, 14, 16)
        layout.setSpacing(0)

        # Logo
        logo = QLabel("⬡  NeuralChat")
        logo.setFont(QFont("Segoe UI", 13, QFont.Bold))
        logo.setStyleSheet(f"color: {C['accent']}; background: transparent;")
        layout.addWidget(logo)
        layout.addSpacing(20)

        # New chat
        new_btn = SidebarButton("＋  New Chat", accent=True)
        new_btn.clicked.connect(self._new_chat)
        layout.addWidget(new_btn)
        layout.addSpacing(20)

        # Divider
        line = QFrame()
        line.setFrameShape(QFrame.HLine)
        line.setStyleSheet(f"color: {C['border']};")
        layout.addWidget(line)
        layout.addSpacing(12)

        # History
        hist_label = QLabel("HISTORY")
        hist_label.setFont(QFont("Segoe UI", 8, QFont.Bold))
        hist_label.setStyleSheet(f"color: {C['dim']}; background: transparent;")
        layout.addWidget(hist_label)
        layout.addSpacing(6)

        self._history_layout = QVBoxLayout()
        self._history_layout.setSpacing(2)
        layout.addLayout(self._history_layout)
        self._add_history("Today's chat")

        layout.addStretch()

        # Bottom model tag
        line2 = QFrame()
        line2.setFrameShape(QFrame.HLine)
        line2.setStyleSheet(f"color: {C['border']};")
        layout.addWidget(line2)
        layout.addSpacing(10)

        model_label = QLabel("⚙  GPT-4.1 nano")
        model_label.setFont(QFont("Segoe UI", 9))
        model_label.setStyleSheet(f"color: {C['dim']}; background: transparent;")
        layout.addWidget(model_label)

        return sb

    def _add_history(self, label: str):
        btn = SidebarButton(f"💬  {label}")
        self._history_layout.addWidget(btn)

    # ── Main panel ────────────────────────────

    def _build_main(self):
        main = QWidget()
        main.setStyleSheet(f"background: {C['bg']};")
        layout = QVBoxLayout(main)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(0)

        layout.addWidget(self._build_topbar())
        layout.addWidget(self._build_chat_area(), stretch=1)
        layout.addWidget(self._build_input_bar())

        return main

    def _build_topbar(self):
        bar = QWidget()
        bar.setFixedHeight(54)
        bar.setStyleSheet(f"background: {C['panel']}; border-bottom: 1px solid {C['border']};")

        layout = QHBoxLayout(bar)
        layout.setContentsMargins(24, 0, 24, 0)

        title = QLabel("New Conversation")
        title.setFont(QFont("Segoe UI", 12, QFont.Bold))
        title.setStyleSheet(f"color: {C['text']}; background: transparent;")

        self._rand_btn = RandomiseButton()
        self._rand_btn.toggled.connect(lambda checked: setattr(self, "_randomise_token", checked))

        status = QLabel("● Online")
        status.setFont(QFont("Segoe UI", 9))
        status.setStyleSheet(f"color: {C['green']}; background: transparent;")

        layout.addWidget(self._rand_btn)
        layout.addSpacing(12)
        layout.addWidget(title)
        layout.addStretch()
        layout.addWidget(status)

        return bar

    def _build_chat_area(self):
        self._scroll = QScrollArea()
        self._scroll.setWidgetResizable(True)
        self._scroll.setStyleSheet(f"""
            QScrollArea {{ border: none; background: {C['bg']}; }}
            QScrollBar:vertical {{
                background: {C['bg']}; width: 6px; margin: 0;
            }}
            QScrollBar::handle:vertical {{
                background: {C['border']}; border-radius: 3px; min-height: 30px;
            }}
            QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical {{ height: 0; }}
        """)

        self._chat_widget = QWidget()
        self._chat_widget.setStyleSheet(f"background: {C['bg']};")
        self._chat_layout = QVBoxLayout(self._chat_widget)
        self._chat_layout.setContentsMargins(0, 16, 0, 16)
        self._chat_layout.setSpacing(4)
        self._chat_layout.addStretch()

        self._scroll.setWidget(self._chat_widget)
        self._add_welcome()

        return self._scroll

    def _build_input_bar(self):
        bar = QWidget()
        bar.setStyleSheet(f"background: {C['bg']};")
        outer = QVBoxLayout(bar)
        outer.setContentsMargins(20, 10, 20, 14)
        outer.setSpacing(6)

        # Input row
        input_frame = QWidget()
        input_frame.setStyleSheet(f"""
            background: {C['input_bg']};
            border: 1px solid {C['border']};
            border-radius: 14px;
        """)
        row = QHBoxLayout(input_frame)
        row.setContentsMargins(14, 8, 8, 8)
        row.setSpacing(8)

        self._input = QTextEdit()
        self._input.setFixedHeight(44)
        self._input.setFont(QFont("Segoe UI", 10))
        self._input.setPlaceholderText("Type a message…")
        self._input.setStyleSheet(f"""
            QTextEdit {{
                background: transparent;
                color: {C['text']};
                border: none;
                selection-background-color: {C['accent']};
            }}
        """)
        self._input.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self._input.installEventFilter(self)

        self._send_btn = SendButton()
        self._send_btn.clicked.connect(self._send)

        row.addWidget(self._input)
        row.addWidget(self._send_btn, alignment=Qt.AlignBottom)

        outer.addWidget(input_frame)

        hint = QLabel("Enter to send  ·  Shift+Enter for newline")
        hint.setFont(QFont("Segoe UI", 8))
        hint.setStyleSheet(f"color: {C['dim']}; background: transparent;")
        hint.setAlignment(Qt.AlignCenter)
        outer.addWidget(hint)

        return bar

    # ── Chat helpers ──────────────────────────

    def _add_welcome(self):
        w = QWidget()
        w.setStyleSheet("background: transparent;")
        vl = QVBoxLayout(w)
        vl.setAlignment(Qt.AlignCenter)
        vl.setSpacing(8)

        icon = QLabel("⬡")
        icon.setFont(QFont("Segoe UI", 40))
        icon.setStyleSheet(f"color: {C['accent']}; background: transparent;")
        icon.setAlignment(Qt.AlignCenter)

        title = QLabel("Hello! How can I help you today?")
        title.setFont(QFont("Segoe UI", 14, QFont.Bold))
        title.setStyleSheet(f"color: {C['text']}; background: transparent;")
        title.setAlignment(Qt.AlignCenter)

        sub = QLabel("Powered by GPT-4.1 nano")
        sub.setFont(QFont("Segoe UI", 9))
        sub.setStyleSheet(f"color: {C['dim']}; background: transparent;")
        sub.setAlignment(Qt.AlignCenter)

        vl.addStretch()
        vl.addWidget(icon)
        vl.addWidget(title)
        vl.addWidget(sub)
        vl.addStretch()

        self._welcome = w
        self._chat_layout.insertWidget(0, w)

    def _remove_welcome(self):
        if hasattr(self, "_welcome") and self._welcome:
            self._welcome.setParent(None)
            self._welcome.deleteLater()
            self._welcome = None

    def _append_message(self, text: str, is_user: bool):
        self._remove_welcome()
        row = make_message_row(text, is_user)
        # Insert before the trailing stretch
        count = self._chat_layout.count()
        self._chat_layout.insertWidget(count - 1, row)
        QTimer.singleShot(50, self._scroll_bottom)

    def _show_typing(self):
        row, dots = make_typing_row()
        count = self._chat_layout.count()
        self._chat_layout.insertWidget(count - 1, row)
        self._typing_row = row
        self._typing_dots = dots
        QTimer.singleShot(50, self._scroll_bottom)

    def _hide_typing(self):
        if self._typing_dots:
            self._typing_dots.stop()
        if self._typing_row:
            self._typing_row.setParent(None)
            self._typing_row.deleteLater()
        self._typing_row = None
        self._typing_dots = None

    def _scroll_bottom(self):
        sb = self._scroll.verticalScrollBar()
        sb.setValue(sb.maximum())

    # ── Send / receive ────────────────────────

    def _send(self):
        text = self._input.toPlainText().strip()
        if not text:
            return
        self._input.clear()
        self._append_message(text, is_user=True)
        self._send_btn.setEnabled(False)
        self._show_typing()

        self._worker = AIWorker(text, self._randomise_token)
        self._worker.response_ready.connect(self._on_response)
        self._worker.start()

    def _on_response(self, answer: str):
        self._hide_typing()
        self._append_message(answer, is_user=False)
        self._send_btn.setEnabled(True)

    def _new_chat(self):
        # Clear all messages
        while self._chat_layout.count() > 1:
            item = self._chat_layout.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        self._welcome = None
        self._add_welcome()
        self._add_history("Previous chat")

    # ── Enter key handling ────────────────────

    def eventFilter(self, obj, event):
        from PyQt5.QtCore import QEvent
        from PyQt5.QtGui import QKeyEvent
        if obj is self._input and event.type() == QEvent.KeyPress:
            key = event.key()
            mods = event.modifiers()
            if key in (Qt.Key_Return, Qt.Key_Enter):
                if mods & Qt.ShiftModifier:
                    return False  # allow newline
                self._send()
                return True
        return super().eventFilter(obj, event)


# ─────────────────────────────────────────────
#  Entry
# ─────────────────────────────────────────────

if __name__ == "__main__":
    app = QApplication(sys.argv)
    app.setStyle("Fusion")

    palette = QPalette()
    palette.setColor(QPalette.Window,      QColor(C["bg"]))
    palette.setColor(QPalette.WindowText,  QColor(C["text"]))
    palette.setColor(QPalette.Base,        QColor(C["surface"]))
    palette.setColor(QPalette.Text,        QColor(C["text"]))
    palette.setColor(QPalette.Button,      QColor(C["panel"]))
    palette.setColor(QPalette.ButtonText,  QColor(C["text"]))
    palette.setColor(QPalette.Highlight,   QColor(C["accent"]))
    app.setPalette(palette)

    win = ChatWindow()
    win.show()
    sys.exit(app.exec_())
