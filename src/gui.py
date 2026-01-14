"""
Samsung Pass to Bitwarden Converter - GUI
A simple Tkinter interface for the converter.
"""

from __future__ import annotations

import json
import threading
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

from src.converter import (
    BitwardenConverter,
    DecryptionError,
    PathValidationError,
)


class ConverterApp:
    """Main application window for Samsung Pass to Bitwarden Converter"""

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Samsung Pass to Bitwarden Converter")
        self.root.geometry("550x400")
        self.root.resizable(True, True)
        self.root.minsize(450, 350)

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

        # Result frame (hidden by default)
        self.result_frame = ttk.Frame(main_frame)
        self.result_label = ttk.Label(self.result_frame, text="")
        self.result_label.pack()

    def _browse_file(self) -> None:
        """Open file browser to select .spass file"""
        filename = filedialog.askopenfilename(
            title="Select Samsung Pass Export File",
            filetypes=[
                ("Samsung Pass files", "*.spass"),
                ("All files", "*.*"),
            ],
        )
        if filename:
            self.file_path_var.set(filename)
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

            output_path = Path(file_path).with_name("bitwarden_export.json")
            with open(output_path, "w", encoding="utf-8") as f:
                json.dump(export_data, f, indent=2)

            item_count = len(export_data["items"])
            self._on_success(str(output_path), item_count)

        except PathValidationError as e:
            self._on_error(f"Path Error:\n{e}")
        except DecryptionError as e:
            self._on_error(
                f"Decryption Error:\n{e}\n\nThis usually means the password is incorrect."
            )
        except Exception as e:
            self._on_error(f"Unexpected Error:\n{e!s}")

    def _on_success(self, output_path: str, item_count: int) -> None:
        """Handle successful conversion (called from background thread)"""

        def update_ui() -> None:
            self.progress.stop()
            self.progress.pack_forget()
            self.convert_btn.configure(state=tk.NORMAL)
            self.status_var.set(f"✓ Success! Exported {item_count} items to:\n{output_path}")
            messagebox.showinfo(
                "Conversion Complete",
                f"Successfully exported {item_count} items!\n\nOutput file:\n{output_path}",
            )

        self.root.after(0, update_ui)

    def _on_error(self, message: str) -> None:
        """Handle conversion error (called from background thread)"""

        def update_ui() -> None:
            self.progress.stop()
            self.progress.pack_forget()
            self.convert_btn.configure(state=tk.NORMAL)
            self.status_var.set("✗ Conversion failed. See error details.")
            messagebox.showerror("Conversion Failed", message)

        self.root.after(0, update_ui)


def main() -> None:
    """Main entry point for GUI application"""
    root = tk.Tk()
    ConverterApp(root)
    root.mainloop()


if __name__ == "__main__":
    main()
