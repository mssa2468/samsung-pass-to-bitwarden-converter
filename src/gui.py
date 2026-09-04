"""
Samsung Pass to Bitwarden Converter - GUI
A simple Tkinter interface for the converter.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any

from src.converter import (
    BitwardenConverter,
    DecryptionError,
    PathValidationError,
    write_bitwarden_export,
)


def _dnd_backend() -> tuple[Any, Any]:
    """tkinterdnd2 names, or (None, None) when drag-and-drop isn't installed."""
    try:
        from tkinterdnd2 import DND_FILES, TkinterDnD

        return DND_FILES, TkinterDnD
    except ImportError:
        return None, None


DND_FILES, TkinterDnD = _dnd_backend()

CONFIG_PATH = Path.home() / ".spass-converter.json"


def _load_last_dir() -> str:
    """Folder last browsed, remembered across runs (best effort)."""
    try:
        return json.loads(CONFIG_PATH.read_text(encoding="utf-8")).get("last_dir", "")
    except (OSError, ValueError):
        return ""


def _save_last_dir(directory: str) -> None:
    try:
        CONFIG_PATH.write_text(json.dumps({"last_dir": directory}), encoding="utf-8")
    except OSError:
        pass


def _open_folder(path: str) -> None:
    """Reveal a folder in the OS file manager."""
    if sys.platform == "win32":
        os.startfile(path)
    elif sys.platform == "darwin":
        subprocess.Popen(["open", path])
    else:
        subprocess.Popen(["xdg-open", path])


class ConverterApp:
    """Main application window for Samsung Pass to Bitwarden Converter"""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Samsung Pass to Bitwarden Converter")
        self.root.geometry("550x400")
        self.root.resizable(True, True)
        self.root.minsize(450, 350)
        self.output_dir: str | None = None
        self.last_dir = _load_last_dir()

        # Configure style
        self.style = ttk.Style()
        self.style.configure("Title.TLabel", font=("Segoe UI", 14, "bold"))
        self.style.configure("Status.TLabel", font=("Segoe UI", 10))

        self._create_widgets()
        self._center_window()

    def _center_window(self) -> None:
        """Center the window on screen"""
        self.root.update_idletasks()
        width = self.root.winfo_width()
        height = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (width // 2)
        y = (self.root.winfo_screenheight() // 2) - (height // 2)
        self.root.geometry(f"{width}x{height}+{x}+{y}")

    def _create_widgets(self) -> None:
        """Create all UI widgets"""
        # Main container with padding
        main_frame = ttk.Frame(self.root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Title
        title_label = ttk.Label(
            main_frame,
            text="Samsung Pass → Bitwarden",
            style="Title.TLabel",
        )
        title_label.pack(pady=(0, 20))

        # File selection frame
        file_frame = ttk.LabelFrame(main_frame, text="Samsung Pass Export File", padding="10")
        file_frame.pack(fill=tk.X, pady=(0, 15))

        self.file_path_var = tk.StringVar()
        file_entry = ttk.Entry(file_frame, textvariable=self.file_path_var, width=50)
        file_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))

        browse_btn = ttk.Button(file_frame, text="Browse...", command=self._browse_file)
        browse_btn.pack(side=tk.RIGHT)

        # Password frame
        password_frame = ttk.LabelFrame(main_frame, text="Export Password", padding="10")
        password_frame.pack(fill=tk.X, pady=(0, 15))

        self.password_var = tk.StringVar()
        password_entry = ttk.Entry(
            password_frame, textvariable=self.password_var, show="•", width=50
        )
        password_entry.pack(fill=tk.X)

        # Show password checkbox
        self.show_password_var = tk.BooleanVar()
        show_password_cb = ttk.Checkbutton(
            password_frame,
            text="Show password",
            variable=self.show_password_var,
            command=lambda: password_entry.configure(
                show="" if self.show_password_var.get() else "•"
            ),
        )
        show_password_cb.pack(anchor=tk.W, pady=(5, 0))

        # Convert button
        self.convert_btn = ttk.Button(
            main_frame,
            text="Convert to Bitwarden",
            command=self._start_conversion,
        )
        self.convert_btn.pack(pady=15)

        # Progress bar (hidden by default)
        self.progress = ttk.Progressbar(main_frame, mode="indeterminate")

        # Status label
        self.status_var = tk.StringVar(value="Ready. Select a .spass file to begin.")
        status_label = ttk.Label(
            main_frame,
            textvariable=self.status_var,
            style="Status.TLabel",
            wraplength=450,
        )
        status_label.pack(pady=(10, 0))

        # Result frame (packed only after a successful conversion)
        self.result_frame = ttk.Frame(main_frame)
        self.open_folder_btn = ttk.Button(
            self.result_frame, text="Open output folder", command=self._open_output_folder
        )
        self.open_folder_btn.pack()

        if TkinterDnD is not None:
            drop_register = getattr(self.root, "drop_target_register", None)
            drop_bind = getattr(self.root, "dnd_bind", None)
            if drop_register is not None and drop_bind is not None:
                drop_register(DND_FILES)
                drop_bind("<<Drop>>", self._on_drop)
                self.status_var.set("Ready. Drop a .spass file or browse to begin.")

    def _browse_file(self) -> None:
        """Open file browser to select .spass file"""
        filename = filedialog.askopenfilename(
            title="Select Samsung Pass Export File",
            initialdir=self.last_dir or None,
            filetypes=[
                ("Samsung Pass files", "*.spass"),
                ("All files", "*.*"),
            ],
        )
        if filename:
            self.file_path_var.set(filename)
            self.last_dir = str(Path(filename).parent)
            _save_last_dir(self.last_dir)
            self.status_var.set("File selected. Enter password and click Convert.")

    def _start_conversion(self) -> None:
        """Start the conversion process in a separate thread"""
        file_path = self.file_path_var.get().strip()
        password = self.password_var.get()

        if not file_path:
            messagebox.showerror("Error", "Please select a .spass file.")
            return

        if not password:
            messagebox.showerror("Error", "Please enter the export password.")
            return

        # Disable button and show progress
        self.convert_btn.configure(state=tk.DISABLED)
        self.result_frame.pack_forget()
        self.progress.pack(fill=tk.X, pady=(0, 10))
        self.progress.start(10)
        self.status_var.set("Converting...")

        # Run conversion in background thread
        thread = threading.Thread(target=self._do_conversion, args=(file_path, password))
        thread.daemon = True
        thread.start()

    def _do_conversion(self, file_path: str, password: str) -> None:
        """Perform the actual conversion (runs in background thread)"""
        try:
            converter = BitwardenConverter()
            export_data = converter.process_file(file_path, password)

            output_path = write_bitwarden_export(file_path, export_data)

            item_count = len(export_data["items"])
            self._on_success(str(output_path), item_count)

        except PathValidationError as e:
            self._on_error(f"Path Error:\n{e}")
        except DecryptionError as e:
            self._on_error(f"Decryption Error:\n{e}")
        except Exception as e:
            self._on_error(f"Unexpected Error:\n{e!s}")

    def _finish(self, update_ui) -> None:
        """Reset progress/button, then run UI update on the main thread."""

        def wrapped() -> None:
            self.progress.stop()
            self.progress.pack_forget()
            self.convert_btn.configure(state=tk.NORMAL)
            update_ui()

        self.root.after(0, wrapped)

    def _on_success(self, output_path: str, item_count: int) -> None:
        """Handle successful conversion (called from background thread)"""

        def update_ui() -> None:
            self.output_dir = str(Path(output_path).parent)
            self.result_frame.pack(pady=(10, 0))
            self.status_var.set(f"✓ Success! Exported {item_count} items to:\n{output_path}")
            messagebox.showinfo(
                "Conversion Complete",
                f"Successfully exported {item_count} items!\n\nOutput file:\n{output_path}",
            )

        self._finish(update_ui)

    def _on_error(self, message: str) -> None:
        """Handle conversion error (called from background thread)"""

        def update_ui() -> None:
            self.result_frame.pack_forget()
            self.status_var.set("✗ Conversion failed. See error details.")
            messagebox.showerror("Conversion Failed", message)

        self._finish(update_ui)

    def _on_drop(self, event) -> None:
        """Use a file dropped onto the window (needs tkinterdnd2)."""
        data = event.data.strip()
        if data.startswith("{"):
            end = data.find("}")
            path = data[1:end] if end != -1 else data.strip("{}")
        else:
            path = data.split()[0]
        if path:
            self.file_path_var.set(path)
            self.last_dir = str(Path(path).parent)
            _save_last_dir(self.last_dir)
            self.status_var.set("File selected. Enter password and click Convert.")

    def _open_output_folder(self) -> None:
        """Reveal the last export folder in the file manager."""
        if self.output_dir:
            _open_folder(self.output_dir)


def main() -> None:
    """Main entry point for GUI application"""
    root = TkinterDnD.Tk() if TkinterDnD is not None else tk.Tk()
    ConverterApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
