
import re
import tkinter as tk
from pathlib import Path
from tkinter import ttk

import pandas as pd
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg


BASE_DIR = Path(__file__).resolve().parent
LOG_FILE = BASE_DIR / "logs" / "security.log"
BLOCKED_IP_FILE = BASE_DIR / "logs" / "blocked_ips.txt"

LOG_PATTERN = re.compile(
    r"^\[(.*?)\] \[(.*?)\] \[(.*?)\] (.*)$"
)


class python_SIEM_SOARApp:
    def __init__(self, root):
        self.root = root
        self.root.title("SIEM & SOAR System")
        self.root.geometry("1000x700")
        self.root.config(bg="#1e1e1e")

        style = ttk.Style()
        style.theme_use("clam")

        self.container = tk.Frame(root, bg="#1e1e1e")
        self.container.pack(fill=tk.BOTH, expand=True)

        self.show_welcome_screen()

    def clear_container(self):
        for widget in self.container.winfo_children():
            widget.destroy()

    def show_welcome_screen(self):
        self.clear_container()

        welcome_frame = tk.Frame(self.container, bg="#1e1e1e")
        welcome_frame.pack(fill=tk.BOTH, expand=True)

        center_box = tk.Frame(
            welcome_frame,
            bg="#2d2d2d",
            padx=40,
            pady=40,
        )
        center_box.place(relx=0.5, rely=0.5, anchor=tk.CENTER)

        tk.Label(
            center_box,
            text="🛡️ SIEM & SOAR",
            font=("Arial", 22, "bold"),
            bg="#2d2d2d",
            fg="#00ffcc",
        ).pack(pady=10)

        tk.Label(
            center_box,
            text=(
                "Python Security Information and Event Management\n"
                "& Automated Response Dashboard"
            ),
            font=("Arial", 11),
            bg="#2d2d2d",
            fg="#cccccc",
            justify=tk.CENTER,
        ).pack(pady=10)

        tk.Button(
            center_box,
            text="🚀 Launch SIEM Dashboard",
            command=self.show_main_dashboard,
            bg="#007acc",
            fg="white",
            font=("Arial", 12, "bold"),
            padx=20,
            pady=10,
            cursor="hand2",
        ).pack(pady=20)

        tk.Label(
            center_box,
            text="Demo Mode: Simulated security events",
            font=("Arial", 9, "italic"),
            bg="#2d2d2d",
            fg="#888888",
        ).pack(pady=5)

    def show_main_dashboard(self):
        self.clear_container()

        sidebar = tk.Frame(
            self.container,
            bg="#252526",
            width=220,
        )
        sidebar.pack(side=tk.LEFT, fill=tk.Y)
        sidebar.pack_propagate(False)

        self.content_area = tk.Frame(
            self.container,
            bg="#1e1e1e",
        )
        self.content_area.pack(
            side=tk.RIGHT,
            fill=tk.BOTH,
            expand=True,
        )

        tk.Label(
            sidebar,
            text="MENU",
            font=("Arial", 12, "bold"),
            bg="#252526",
            fg="#00ffcc",
        ).pack(pady=20)

        btn_style = {
            "bg": "#2d2d2d",
            "fg": "white",
            "font": ("Arial", 10),
            "bd": 0,
            "padx": 15,
            "pady": 10,
            "anchor": "w",
            "cursor": "hand2",
        }

        tk.Button(
            sidebar,
            text="📋 Security Logs",
            command=self.load_logs_view,
            **btn_style,
        ).pack(fill=tk.X, padx=10, pady=5)

        tk.Button(
            sidebar,
            text="📊 Analytics & Charts",
            command=self.load_charts_view,
            **btn_style,
        ).pack(fill=tk.X, padx=10, pady=5)

        tk.Button(
            sidebar,
            text="🚫 SOAR Recorded IPs",
            command=self.load_blocked_ips_view,
            **btn_style,
        ).pack(fill=tk.X, padx=10, pady=5)

        tk.Frame(
            sidebar,
            bg="#252526",
            height=200,
        ).pack(fill=tk.BOTH, expand=True)

        tk.Button(
            sidebar,
            text="⬅️ Back to Home",
            command=self.show_welcome_screen,
            bg="#a83232",
            fg="white",
            font=("Arial", 10, "bold"),
            bd=0,
            padx=15,
            pady=8,
            anchor="w",
            cursor="hand2",
        ).pack(fill=tk.X, padx=10, pady=20)

        self.load_logs_view()

    def clear_content(self):
        for widget in self.content_area.winfo_children():
            widget.destroy()

    def create_header(self, title, refresh_command):
        header_frame = tk.Frame(
            self.content_area,
            bg="#1e1e1e",
        )
        header_frame.pack(fill=tk.X, padx=20, pady=15)

        tk.Label(
            header_frame,
            text=title,
            font=("Arial", 14, "bold"),
            bg="#1e1e1e",
            fg="white",
        ).pack(side=tk.LEFT)

        tk.Button(
            header_frame,
            text="🔄 Refresh",
            command=refresh_command,
            bg="#007acc",
            fg="white",
            font=("Arial", 9, "bold"),
            padx=10,
            pady=3,
            cursor="hand2",
        ).pack(side=tk.RIGHT)

    def load_logs_view(self):
        self.clear_content()
        self.create_header(
            "📋 Security Logs",
            self.load_logs_view,
        )

        table_frame = tk.Frame(
            self.content_area,
            bg="#1e1e1e",
        )
        table_frame.pack(
            fill=tk.BOTH,
            expand=True,
            padx=20,
            pady=10,
        )

        log_tree = ttk.Treeview(
            table_frame,
            columns=("Timestamp", "Level", "Event Type", "Message"),
            show="headings",
        )

        columns = {
            "Timestamp": ("Timestamp", 150, tk.CENTER),
            "Level": ("Level", 80, tk.CENTER),
            "Event Type": ("Event Type", 160, tk.CENTER),
            "Message": ("Message", 400, tk.W),
        }

        for column, (heading, width, anchor) in columns.items():
            log_tree.heading(column, text=heading)
            log_tree.column(
                column,
                width=width,
                anchor=anchor,
            )

        scrollbar = ttk.Scrollbar(
            table_frame,
            orient=tk.VERTICAL,
            command=log_tree.yview,
        )
        log_tree.configure(yscrollcommand=scrollbar.set)

        log_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)

        if not LOG_FILE.exists():
            log_tree.insert(
                "",
                tk.END,
                values=("-", "-", "-", "No log file available yet."),
            )
            return

        try:
            with LOG_FILE.open("r", encoding="utf-8") as file:
                for line in file:
                    match = LOG_PATTERN.match(line.strip())

                    if match:
                        timestamp, level, event_type, message = (
                            match.groups()
                        )
                        log_tree.insert(
                            "",
                            tk.END,
                            values=(
                                timestamp,
                                level,
                                event_type,
                                message,
                            ),
                        )

        except OSError as error:
            log_tree.insert(
                "",
                tk.END,
                values=("-", "ERROR", "-", str(error)),
            )

    def load_charts_view(self):
        self.clear_content()
        self.create_header(
            "📊 Threat & Event Analytics",
            self.load_charts_view,
        )

        chart_container = tk.Frame(
            self.content_area,
            bg="#2d2d2d",
        )
        chart_container.pack(
            fill=tk.BOTH,
            expand=True,
            padx=20,
            pady=10,
        )

        if not LOG_FILE.exists():
            self.show_chart_message(
                chart_container,
                "No log data available yet.",
            )
            return

        parsed_data = []

        try:
            with LOG_FILE.open("r", encoding="utf-8") as file:
                for line in file:
                    match = LOG_PATTERN.match(line.strip())

                    if match:
                        _, _, event_type, _ = match.groups()
                        parsed_data.append(
                            {"Event_Type": event_type}
                        )

        except OSError as error:
            self.show_chart_message(
                chart_container,
                f"Could not read log file: {error}",
            )
            return

        if not parsed_data:
            self.show_chart_message(
                chart_container,
                "No valid security events found yet.",
            )
            return

        df = pd.DataFrame(parsed_data)
        event_counts = df["Event_Type"].value_counts()

        fig, ax = plt.subplots(figsize=(6, 4))
        fig.patch.set_facecolor("#2d2d2d")
        ax.set_facecolor("#1e1e1e")

        event_counts.plot(
            kind="bar",
            ax=ax,
            color="#007acc",
        )

        ax.set_title(
            "Events Distribution by Type",
            color="white",
            fontsize=11,
        )
        ax.tick_params(axis="x", colors="white", rotation=20)
        ax.tick_params(axis="y", colors="white")

        ax.spines["bottom"].set_color("white")
        ax.spines["left"].set_color("white")
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)

        fig.tight_layout()

        canvas = FigureCanvasTkAgg(
            fig,
            master=chart_container,
        )
        canvas.draw()
        canvas.get_tk_widget().pack(
            fill=tk.BOTH,
            expand=True,
            padx=10,
            pady=10,
        )

        plt.close(fig)

    def show_chart_message(self, parent, message):
        tk.Label(
            parent,
            text=message,
            bg="#2d2d2d",
            fg="#cccccc",
            font=("Arial", 11),
        ).pack(expand=True)

    def load_blocked_ips_view(self):
        self.clear_content()
        self.create_header(
            "🚫 SOAR Recorded IPs (Simulation)",
            self.load_blocked_ips_view,
        )

        list_frame = tk.Frame(
            self.content_area,
            bg="#2d2d2d",
            padx=15,
            pady=15,
        )
        list_frame.pack(
            fill=tk.BOTH,
            expand=True,
            padx=20,
            pady=10,
        )

        tk.Label(
            list_frame,
            text=(
                "IP addresses recorded by the SOAR simulation. "
                "No real firewall rules are changed."
            ),
            font=("Arial", 10),
            bg="#2d2d2d",
            fg="#cccccc",
            wraplength=650,
            justify=tk.LEFT,
        ).pack(anchor="w", pady=(0, 10))

        blocked_listbox = tk.Listbox(
            list_frame,
            bg="#1e1e1e",
            fg="#ff5555",
            font=("Courier", 12, "bold"),
            bd=0,
        )
        blocked_listbox.pack(
            fill=tk.BOTH,
            expand=True,
            padx=5,
            pady=5,
        )

        if not BLOCKED_IP_FILE.exists():
            blocked_listbox.insert(
                tk.END,
                "No IP addresses recorded yet.",
            )
            return

        try:
            with BLOCKED_IP_FILE.open(
                "r",
                encoding="utf-8",
            ) as file:
                ips = [
                    line.strip()
                    for line in file
                    if line.strip()
                ]

            if not ips:
                blocked_listbox.insert(
                    tk.END,
                    "No IP addresses recorded yet.",
                )
            else:
                for ip in ips:
                    blocked_listbox.insert(
                        tk.END,
                        f"  SIMULATED: {ip}",
                    )

        except OSError as error:
            blocked_listbox.insert(
                tk.END,
                f"Could not read IP list: {error}",
            )


if __name__ == "__main__":
    root = tk.Tk()
    app = python_SIEM_SOARApp(root)
    root.mainloop()
