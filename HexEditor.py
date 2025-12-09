#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cross-platform Hex Editor with malware analysis capabilities.
Supports Windows, Linux, and macOS.
"""

import tkinter as tk
from tkinter import filedialog, messagebox, scrolledtext, ttk
import os
import sys
import platform
import struct
import random
import string
import math
import hashlib
import re
import webbrowser

# Platform detection
IS_WINDOWS = platform.system() == 'Windows'
IS_LINUX = platform.system() == 'Linux'
IS_MAC = platform.system() == 'Darwin'


class HexEditor:
    def __init__(self, root):
        self.root = root
        self.root.title("Hex Editor")
        self.root.geometry("1000x800")  # Increased height for assembler
        
        self.current_file = None
        self.data = bytearray()
        self.modified = False
        self.editing_offset = None
        self.edit_entry = None
        self.edit_mode = 'hex'
        self.current_encoding = 'ASCII'
        self.pe_sections = []  # Store PE section info
        self.malware_detections = []  # Store malware detection offsets (filtered)
        self.all_malware_detections = []  # Store all malware detections (unfiltered)
        self.current_detection_index = -1  # Track current detection for navigation
        self.analysis_dialog = None  # Track analysis dialog window
        self.analysis_text_widget = None  # Track analysis text widget
        self.auto_select_encoding = tk.BooleanVar(value=False)  # Auto-select encoding when navigating
        self.threat_filter = None  # Track threat filter dropdown
        self.assembled_bytes = bytearray()  # Store assembled bytes
        self.hex_click_offset = None  # Store offset from right-click in hex editor
        
        self.setup_menu()
        self.setup_ui()
        
    def setup_menu(self):
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Open", command=self.open_file, accelerator="Ctrl+O")
        file_menu.add_command(label="Save", command=self.save_file, accelerator="Ctrl+S")
        file_menu.add_command(label="Save As", command=self.save_file_as, accelerator="Ctrl+Shift+S")
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.exit_app)
        
        # Edit menu
        edit_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Edit", menu=edit_menu)
        edit_menu.add_command(label="Find", command=self.show_find_dialog, accelerator="Ctrl+F")
        edit_menu.add_command(label="Go to Offset", command=self.show_goto_dialog, accelerator="Ctrl+G")
        
        # View menu
        view_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="View", menu=view_menu)
        view_menu.add_command(label="PE Info (EXE/DLL)", command=self.show_pe_info, accelerator="Ctrl+I")
        view_menu.add_command(label="Edit Metadata", command=self.show_metadata_editor, accelerator="Ctrl+M")
        
        # Analysis menu
        analysis_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Analysis", menu=analysis_menu)
        analysis_menu.add_command(label="Malware Analysis Tools", command=self.show_malware_analysis_tools, accelerator="Ctrl+A")
        
        # Bind keyboard shortcuts (both cases for cross-platform compatibility)
        self.root.bind("<Control-o>", lambda e: self.open_file())
        self.root.bind("<Control-O>", lambda e: self.open_file())
        self.root.bind("<Control-s>", lambda e: self.save_file())
        self.root.bind("<Control-S>", lambda e: self.save_file())
        self.root.bind("<Control-Shift-S>", lambda e: self.save_file_as())
        self.root.bind("<Control-Shift-s>", lambda e: self.save_file_as())
        self.root.bind("<Control-f>", lambda e: self.show_find_dialog())
        self.root.bind("<Control-F>", lambda e: self.show_find_dialog())
        self.root.bind("<Control-g>", lambda e: self.show_goto_dialog())
        self.root.bind("<Control-G>", lambda e: self.show_goto_dialog())
        self.root.bind("<Control-i>", lambda e: self.show_pe_info())
        self.root.bind("<Control-I>", lambda e: self.show_pe_info())
        self.root.bind("<Control-m>", lambda e: self.show_metadata_editor())
        self.root.bind("<Control-M>", lambda e: self.show_metadata_editor())
        self.root.bind("<Control-a>", lambda e: self.show_malware_analysis_tools())
        self.root.bind("<Control-A>", lambda e: self.show_malware_analysis_tools())
        self.root.bind("<F3>", lambda e: self.next_detection())
        self.root.bind("<Shift-F3>", lambda e: self.prev_detection())
        
    def setup_ui(self):
        # Toolbar
        self.toolbar = tk.Frame(self.root, relief=tk.RAISED, borderwidth=1)
        self.toolbar.pack(side=tk.TOP, fill=tk.X)
        
        tk.Button(self.toolbar, text="Open", command=self.open_file).pack(side=tk.LEFT, padx=2, pady=2)
        tk.Button(self.toolbar, text="Save", command=self.save_file).pack(side=tk.LEFT, padx=2, pady=2)
        tk.Button(self.toolbar, text="Find", command=self.show_find_dialog).pack(side=tk.LEFT, padx=2, pady=2)
        tk.Button(self.toolbar, text="Go to", command=self.show_goto_dialog).pack(side=tk.LEFT, padx=2, pady=2)
        
        # Malware scan button (initially hidden, shown only for executables)
        self.malware_scan_button = tk.Button(self.toolbar, text="Scan for Malware", command=self.scan_malware, bg="#FF5722", fg="white")
        
        # Check errors button (initially hidden, shown only for executables)
        self.check_errors_button = tk.Button(self.toolbar, text="Check Errors", command=self.check_program_errors, bg="#9C27B0", fg="white")
        
        # Malware navigation buttons (initially hidden)
        self.malware_nav_frame = tk.Frame(self.toolbar, relief=tk.SUNKEN, borderwidth=1)
        tk.Label(self.malware_nav_frame, text="Detections:", fg="red", font=("Arial", 9, "bold")).pack(side=tk.LEFT, padx=2)
        self.detection_label = tk.Label(self.malware_nav_frame, text="0/0", font=("Arial", 9))
        self.detection_label.pack(side=tk.LEFT, padx=2)
        
        # Threat level filter dropdown
        self.threat_filter_var = tk.StringVar(value='All Threats')
        self.threat_filter = ttk.Combobox(self.malware_nav_frame, textvariable=self.threat_filter_var,
                                          values=['All Threats', 'High Risk', 'Moderate Risk', 'Low Risk'],
                                          state='readonly', width=12)
        self.threat_filter.pack(side=tk.LEFT, padx=3)
        self.threat_filter.bind('<<ComboboxSelected>>', self.on_threat_filter_change)
        
        tk.Button(self.malware_nav_frame, text="◄ Prev", command=self.prev_detection, width=6).pack(side=tk.LEFT, padx=1)
        tk.Button(self.malware_nav_frame, text="Next ►", command=self.next_detection, width=6).pack(side=tk.LEFT, padx=1)
        tk.Button(self.malware_nav_frame, text="Clear", command=self.clear_detections, width=5).pack(side=tk.LEFT, padx=1)
        
        # Encoding selector
        tk.Label(self.toolbar, text="Encoding:").pack(side=tk.LEFT, padx=(10, 2), pady=2)
        self.encoding_var = tk.StringVar(value='ASCII')
        encoding_dropdown = ttk.Combobox(self.toolbar, textvariable=self.encoding_var, 
                                        values=['ASCII', 'UTF-8', 'UTF-16LE', 'UTF-16BE', 'UTF-32LE', 'UTF-32BE', 
                                               'Latin-1', 'CP1252', 'CP437 (DOS)', 'CP850 (DOS)', 'CP866 (DOS Cyrillic)',
                                               'Shift-JIS', 'GB2312 (Chinese)', 'EUC-KR (Korean)', 'ISO-8859-1',
                                               'ISO-8859-15', 'KOI8-R (Russian)', 'Base64', 'Hex Escaped', 'ROT13'],
                                        state='readonly', width=15)
        encoding_dropdown.pack(side=tk.LEFT, padx=2, pady=2)
        encoding_dropdown.bind('<<ComboboxSelected>>', self.on_encoding_change)
        
        # Status bar
        self.status_bar = tk.Label(self.root, text="Ready", bd=1, relief=tk.SUNKEN, anchor=tk.W)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
        
        # Malware explanation panel (initially hidden)
        self.malware_info_frame = tk.Frame(self.root, relief=tk.RAISED, borderwidth=2, bg="#fff3cd")
        malware_title = tk.Label(self.malware_info_frame, text="⚠ Detection Info:", 
                                font=("Arial", 10, "bold"), bg="#fff3cd", fg="#856404")
        malware_title.pack(side=tk.LEFT, padx=5, pady=5)
        self.malware_info_label = tk.Label(self.malware_info_frame, text="", 
                                          font=("Arial", 9), bg="#fff3cd", fg="#856404",
                                          wraplength=700, justify=tk.LEFT)
        self.malware_info_label.pack(side=tk.LEFT, padx=5, pady=5, fill=tk.X, expand=True)
        self.analyze_button = tk.Button(self.malware_info_frame, text="🔍 Further Analyze", 
                                       command=self.further_analyze_detection,
                                       bg="#ffc107", fg="#000", font=("Arial", 9, "bold"),
                                       relief=tk.RAISED, padx=10, pady=3)
        self.analyze_button.pack(side=tk.RIGHT, padx=5, pady=5)
        
        # Main container with PanedWindow for resizable sections
        main_paned = tk.PanedWindow(self.root, orient=tk.VERTICAL, sashwidth=5, bg="#cccccc")
        main_paned.pack(side=tk.TOP, fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # ===== AUTO ASSEMBLER SECTION =====
        self.assembler_frame = tk.Frame(main_paned, relief=tk.RAISED, borderwidth=1)
        main_paned.add(self.assembler_frame, minsize=100)
        
        # Assembler header
        asm_header = tk.Frame(self.assembler_frame, bg="#1565C0", height=30)
        asm_header.pack(fill=tk.X)
        asm_header.pack_propagate(False)
        tk.Label(asm_header, text="⚙ Auto Assembler", font=("Arial", 10, "bold"), 
                bg="#1565C0", fg="white").pack(side=tk.LEFT, padx=10, pady=3)
        
        # Assembler controls
        asm_controls = tk.Frame(self.assembler_frame, bg="#e3f2fd")
        asm_controls.pack(fill=tk.X, padx=5, pady=3)
        
        tk.Label(asm_controls, text="Architecture:", bg="#e3f2fd", font=("Arial", 9)).pack(side=tk.LEFT, padx=5)
        self.asm_arch_var = tk.StringVar(value="x86")
        arch_combo = ttk.Combobox(asm_controls, textvariable=self.asm_arch_var, 
                                  values=["x86", "x64"], state='readonly', width=6)
        arch_combo.pack(side=tk.LEFT, padx=3)
        
        tk.Label(asm_controls, text="Base Address:", bg="#e3f2fd", font=("Arial", 9)).pack(side=tk.LEFT, padx=(15,5))
        self.asm_base_var = tk.StringVar(value="0x00400000")
        base_entry = tk.Entry(asm_controls, textvariable=self.asm_base_var, width=12, font=("Courier", 9))
        base_entry.pack(side=tk.LEFT, padx=3)
        
        tk.Button(asm_controls, text="▶ Assemble", command=self.assemble_code, 
                 bg="#4CAF50", fg="white", font=("Arial", 9, "bold")).pack(side=tk.LEFT, padx=10)
        tk.Button(asm_controls, text="📋 Copy Bytes", command=self.copy_assembled_bytes, 
                 bg="#2196F3", fg="white", font=("Arial", 9)).pack(side=tk.LEFT, padx=3)
        tk.Button(asm_controls, text="💉 Inject at Selection", command=self.inject_assembled_bytes, 
                 bg="#FF5722", fg="white", font=("Arial", 9)).pack(side=tk.LEFT, padx=3)
        
        # Toggle button to show/hide assembler
        self.asm_visible = tk.BooleanVar(value=True)
        tk.Checkbutton(asm_controls, text="Show Assembler", variable=self.asm_visible, 
                      command=self.toggle_assembler, bg="#e3f2fd", font=("Arial", 8)).pack(side=tk.RIGHT, padx=10)
        
        # Assembler content area
        asm_content = tk.Frame(self.assembler_frame)
        asm_content.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Left side: Assembly input
        asm_input_frame = tk.Frame(asm_content)
        asm_input_frame.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        tk.Label(asm_input_frame, text="Assembly Code:", font=("Arial", 9, "bold")).pack(anchor='w')
        
        asm_input_scroll = tk.Scrollbar(asm_input_frame)
        asm_input_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.asm_input = tk.Text(asm_input_frame, height=6, font=("Courier", 10), 
                                 wrap=tk.NONE, yscrollcommand=asm_input_scroll.set)
        self.asm_input.pack(fill=tk.BOTH, expand=True)
        asm_input_scroll.config(command=self.asm_input.yview)
        
        # Insert example code
        self.asm_input.insert(tk.END, "; Example x86 assembly\n")
        self.asm_input.insert(tk.END, "push ebp\n")
        self.asm_input.insert(tk.END, "mov ebp, esp\n")
        self.asm_input.insert(tk.END, "xor eax, eax\n")
        self.asm_input.insert(tk.END, "pop ebp\n")
        self.asm_input.insert(tk.END, "ret\n")
        
        # Right side: Output (bytes + disassembly)
        asm_output_frame = tk.Frame(asm_content)
        asm_output_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True, padx=(10, 0))
        
        tk.Label(asm_output_frame, text="Machine Code Output:", font=("Arial", 9, "bold")).pack(anchor='w')
        
        asm_output_scroll = tk.Scrollbar(asm_output_frame)
        asm_output_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        self.asm_output = tk.Text(asm_output_frame, height=6, font=("Courier", 10), 
                                  wrap=tk.NONE, yscrollcommand=asm_output_scroll.set, bg="#f5f5f5")
        self.asm_output.pack(fill=tk.BOTH, expand=True)
        asm_output_scroll.config(command=self.asm_output.yview)
        self.asm_output.config(state=tk.DISABLED)
        
        # Right-click context menu for assembler output
        self.asm_output_menu = tk.Menu(self.asm_output, tearoff=0)
        self.asm_output_menu.add_command(label="Copy Address", command=self.copy_asm_address)
        self.asm_output_menu.add_command(label="Copy Bytes", command=self.copy_asm_line_bytes)
        self.asm_output_menu.add_command(label="Copy Line", command=self.copy_asm_line)
        self.asm_output_menu.add_separator()
        self.asm_output_menu.add_command(label="Copy All Bytes", command=self.copy_assembled_bytes)
        
        def show_asm_output_menu(event):
            # Get the line under cursor
            self.asm_output.config(state=tk.NORMAL)
            self.asm_output.tag_remove("sel", 1.0, tk.END)
            # Get line at click position
            index = self.asm_output.index(f"@{event.x},{event.y}")
            line_start = self.asm_output.index(f"{index} linestart")
            line_end = self.asm_output.index(f"{index} lineend")
            self.asm_output.tag_add("sel", line_start, line_end)
            self.asm_output.config(state=tk.DISABLED)
            self.asm_output_menu.post(event.x_root, event.y_root)
        
        self.asm_output.bind("<Button-3>", show_asm_output_menu)
        
        # Store assembled bytes
        self.assembled_bytes = bytearray()
        
        # ===== HEX VIEWER SECTION =====
        main_frame = tk.Frame(main_paned)
        main_paned.add(main_frame, minsize=200)

        
        # Sidebar for PE sections (initially hidden)
        self.sidebar_frame = tk.Frame(main_frame, width=150, relief=tk.RAISED, borderwidth=1)
        self.sidebar_label = tk.Label(self.sidebar_frame, text="PE Sections", font=("Arial", 10, "bold"), bg="#e0e0e0")
        self.sidebar_label.pack(fill=tk.X, pady=5)
        
        self.sections_canvas = tk.Canvas(self.sidebar_frame, bg="white")
        sections_scrollbar = tk.Scrollbar(self.sidebar_frame, orient=tk.VERTICAL, command=self.sections_canvas.yview)
        self.sections_scrollable = tk.Frame(self.sections_canvas, bg="white")
        
        self.sections_scrollable.bind(
            "<Configure>",
            lambda e: self.sections_canvas.configure(scrollregion=self.sections_canvas.bbox("all"))
        )
        
        self.sections_canvas.create_window((0, 0), window=self.sections_scrollable, anchor="nw")
        self.sections_canvas.configure(yscrollcommand=sections_scrollbar.set)
        
        self.sections_canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sections_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Create text widget with scrollbar
        self.text_frame = tk.Frame(main_frame)
        self.text_frame.pack(side=tk.RIGHT, fill=tk.BOTH, expand=True)
        
        # Scrollbar
        scrollbar = tk.Scrollbar(self.text_frame)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Text widget with custom scroll callback
        def on_text_scroll(*args):
            scrollbar.set(*args)
            self.update_disassembly_view()
        
        self.text_widget = tk.Text(self.text_frame, wrap=tk.NONE, font=("Courier", 10),
                                   yscrollcommand=on_text_scroll)
        self.text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        def scroll_and_update(*args):
            self.text_widget.yview(*args)
            self.update_disassembly_view()
        
        scrollbar.config(command=scroll_and_update)
        
        # Track current view offset for disassembly
        self.current_view_offset = 0
        
        # Bind mouse wheel scrolling (cross-platform)
        def on_mousewheel(event):
            if IS_WINDOWS or IS_MAC:
                self.text_widget.yview_scroll(int(-1*(event.delta/120)), "units")
            self.update_disassembly_view()
        
        def on_mousewheel_linux(event, direction):
            self.text_widget.yview_scroll(direction, "units")
            self.update_disassembly_view()
        
        if IS_LINUX:
            self.text_widget.bind("<Button-4>", lambda e: on_mousewheel_linux(e, -3))
            self.text_widget.bind("<Button-5>", lambda e: on_mousewheel_linux(e, 3))
        else:
            self.text_widget.bind("<MouseWheel>", on_mousewheel)
        
        # Configure tags for highlighting
        self.text_widget.tag_config("offset", foreground="#666666")
        self.text_widget.tag_config("hex", foreground="#0000FF")
        self.text_widget.tag_config("ascii", foreground="#008000")
        self.text_widget.tag_config("highlight", background="#FFFF00")
        self.text_widget.tag_config("editing", background="#FFE0B2")
        self.text_widget.tag_config("malware", background="#FF0000", foreground="#FFFFFF")
        self.text_widget.tag_config("changed_hex", background="#90EE90", foreground="#006400")  # Light green bg, dark green text
        self.text_widget.tag_config("changed_ascii", background="#90EE90", foreground="#006400")  # Light green bg, dark green text
        
        # Track pending highlight removals
        self.pending_highlight_removals = []
        
        # Right-click context menu for hex editor
        self.hex_context_menu = tk.Menu(self.text_widget, tearoff=0)
        self.hex_context_menu.add_command(label="Copy Address", command=self.copy_hex_address)
        self.hex_context_menu.add_command(label="Copy Byte", command=self.copy_hex_byte)
        self.hex_context_menu.add_command(label="Copy Selection", command=self.copy_hex_selection)
        self.hex_context_menu.add_separator()
        self.hex_context_menu.add_command(label="Go to Address...", command=self.show_goto_dialog)
        self.hex_context_menu.add_command(label="Find...", command=self.show_find_dialog)
        
        self.hex_click_offset = None  # Store offset from right-click
        
        def show_hex_context_menu(event):
            # Get offset at click position
            index = self.text_widget.index(f"@{event.x},{event.y}")
            line, col = map(int, index.split('.'))
            
            # Calculate offset from line and column
            # Line format: "00000000  XX XX XX XX XX XX XX XX  XX XX XX XX XX XX XX XX  |................|"
            # Offset column is 0-7, hex starts at 10
            if col < 10:
                # Clicked on offset - get it directly
                line_text = self.text_widget.get(f"{line}.0", f"{line}.8")
                try:
                    self.hex_click_offset = int(line_text, 16)
                except:
                    self.hex_click_offset = None
            elif col >= 10 and col < 58:
                # Clicked on hex area
                line_text = self.text_widget.get(f"{line}.0", f"{line}.8")
                try:
                    base_offset = int(line_text, 16)
                    # Calculate which byte (accounting for spaces)
                    hex_col = col - 10
                    if hex_col >= 25:  # After the middle gap
                        hex_col -= 1
                    byte_index = hex_col // 3
                    self.hex_click_offset = base_offset + byte_index
                except:
                    self.hex_click_offset = None
            elif col >= 60:
                # Clicked on ASCII area
                line_text = self.text_widget.get(f"{line}.0", f"{line}.8")
                try:
                    base_offset = int(line_text, 16)
                    ascii_col = col - 61  # After "|"
                    if ascii_col >= 0 and ascii_col < 16:
                        self.hex_click_offset = base_offset + ascii_col
                except:
                    self.hex_click_offset = None
            
            self.hex_context_menu.post(event.x_root, event.y_root)
        
        self.text_widget.bind("<Button-3>", show_hex_context_menu)
        
        # Bind events
        self.text_widget.bind("<Button-1>", self.on_click)
        self.text_widget.bind("<KeyPress>", self.on_key_press)
        
    def open_file(self):
        if self.modified:
            response = messagebox.askyesnocancel("Save Changes", 
                                                  "Do you want to save changes before opening a new file?")
            if response is None:  # Cancel
                return
            elif response:  # Yes
                self.save_file()
        
        filepath = filedialog.askopenfilename(title="Open File")
        if filepath:
            try:
                with open(filepath, 'rb') as f:
                    self.data = bytearray(f.read())
                self.current_file = filepath
                self.modified = False
                self.close_editor()
                self.clear_detections()
                
                # Hide malware scan button until we determine file type
                self.malware_scan_button.pack_forget()
                self.check_errors_button.pack_forget()
                
                # Auto-detect best encoding
                self.auto_detect_encoding()
                
                self.display_hex()
                
                # Check if it's an EXE/DLL and show info
                file_ext = os.path.splitext(filepath)[1].lower()
                # Windows executables
                windows_exts = ['.exe', '.dll', '.sys', '.ocx', '.scr', '.drv', '.cpl', '.msi', '.bat', '.cmd', '.ps1', '.vbs', '.js', '.jar', '.com']
                # Linux/Unix executables
                linux_exts = ['.so', '.o', '.ko', '.elf', '.bin', '.sh', '.run', '.appimage']
                # All executable extensions
                executable_extensions = windows_exts + linux_exts
                
                # Also check for ELF magic number (Linux executables)
                is_elf = len(self.data) >= 4 and self.data[:4] == b'\x7fELF'
                is_executable = file_ext in executable_extensions or self.is_pe_file() or is_elf or self.is_executable_file(filepath)
                
                if is_executable:
                    # Show malware scan button for executable files
                    self.malware_scan_button.pack(side=tk.LEFT, padx=2, pady=2)
                    self.malware_scan_button.lift()  # Bring to front
                    
                    # Show check errors button for executable files
                    self.check_errors_button.pack(side=tk.LEFT, padx=2, pady=2)
                    self.check_errors_button.lift()
                    
                    if self.is_pe_file():
                        self.parse_pe_sections()
                        self.show_pe_sidebar()
                        self.update_status(f"Opened: {os.path.basename(filepath)} ({len(self.data)} bytes) - PE Executable detected. Press Ctrl+I for info")
                    else:
                        self.hide_pe_sidebar()
                        self.update_status(f"Opened: {os.path.basename(filepath)} ({len(self.data)} bytes) - Executable file")
                else:
                    # Hide malware scan button for non-executable files
                    self.malware_scan_button.pack_forget()
                    self.check_errors_button.pack_forget()
                    self.hide_pe_sidebar()
                    self.update_status(f"Opened: {os.path.basename(filepath)} ({len(self.data)} bytes)")
                
                self.root.title(f"Hex Editor - {os.path.basename(filepath)}")
                
                # Update disassembly view
                self.update_disassembly_view()
            except Exception as e:
                messagebox.showerror("Error", f"Could not open file:\n{str(e)}")
    
    def save_file(self):
        if self.current_file:
            try:
                with open(self.current_file, 'wb') as f:
                    f.write(self.data)
                self.modified = False
                self.update_status(f"Saved: {os.path.basename(self.current_file)}")
                self.root.title(f"Hex Editor - {os.path.basename(self.current_file)}")
            except Exception as e:
                messagebox.showerror("Error", f"Could not save file:\n{str(e)}")
        else:
            self.save_file_as()
    
    def save_file_as(self):
        filepath = filedialog.asksaveasfilename(title="Save File As")
        if filepath:
            self.current_file = filepath
            self.save_file()
    
    def display_hex(self):
        self.text_widget.config(state=tk.NORMAL)
        self.text_widget.delete(1.0, tk.END)
        
        if not self.data:
            self.text_widget.config(state=tk.DISABLED)
            return
        
        bytes_per_line = 16
        lines = []
        
        for i in range(0, len(self.data), bytes_per_line):
            chunk = self.data[i:i + bytes_per_line]
            
            # Offset
            offset = f"{i:08X}  "
            
            # Hex values
            hex_part = ""
            for j, byte in enumerate(chunk):
                hex_part += f"{byte:02X} "
                if j == 7:
                    hex_part += " "
            
            # Pad hex part if line is short
            hex_part = hex_part.ljust(50)
            
            # Text representation based on encoding
            text_part = self.get_text_representation(chunk)
            
            line = offset + hex_part + " " + text_part + "\n"
            lines.append(line)
        
        self.text_widget.insert(1.0, "".join(lines))
        self.apply_syntax_highlighting()
        
    def apply_syntax_highlighting(self):
        content = self.text_widget.get(1.0, tk.END)
        lines = content.split("\n")
        
        for line_num, line in enumerate(lines, start=1):
            if len(line) < 10:
                continue
            
            # Highlight offset (first 8 chars + 2 spaces)
            self.text_widget.tag_add("offset", f"{line_num}.0", f"{line_num}.10")
            
            # Highlight hex values (chars 10-58)
            if len(line) > 10:
                hex_end = min(len(line), 60)
                self.text_widget.tag_add("hex", f"{line_num}.10", f"{line_num}.{hex_end}")
            
            # Highlight ASCII (after position 60)
            if len(line) > 60:
                self.text_widget.tag_add("ascii", f"{line_num}.61", f"{line_num}.{len(line)}")
    
    def on_click(self, event):
        # Close any open editor first
        self.close_editor()
        
        # Get cursor position
        index = self.text_widget.index(f"@{event.x},{event.y}")
        line, col = map(int, index.split('.'))
        
        # Calculate byte offset and start editing
        if 10 <= col <= 58:  # Hex area
            byte_offset = self.get_byte_offset_from_position(line, col)
            if byte_offset is not None and byte_offset < len(self.data):
                self.start_editing(line, col, byte_offset, edit_mode='hex')
        elif col >= 61:  # ASCII area
            byte_offset = self.get_byte_offset_from_ascii_position(line, col)
            if byte_offset is not None and byte_offset < len(self.data):
                self.start_editing(line, col, byte_offset, edit_mode='ascii')
        
        return "break"
    
    def get_byte_offset_from_position(self, line, col):
        line_offset = (line - 1) * 16
        
        if 10 <= col < 34:  # First 8 bytes
            byte_in_line = (col - 10) // 3
        elif 35 <= col < 59:  # Second 8 bytes
            byte_in_line = 8 + (col - 35) // 3
        else:
            return None
        
        return line_offset + byte_in_line
    
    def get_byte_offset_from_ascii_position(self, line, col):
        line_offset = (line - 1) * 16
        byte_in_line = col - 61
        
        if 0 <= byte_in_line < 16:
            return line_offset + byte_in_line
        return None
    
    def start_editing(self, line, col, offset, edit_mode='hex'):
        # Don't start if already editing
        if self.editing_offset is not None and self.edit_entry is not None:
            return
        
        self.editing_offset = offset
        self.edit_mode = edit_mode
        
        # Calculate exact position based on edit mode
        byte_in_line = offset % 16
        
        if edit_mode == 'hex':
            # Calculate position for hex byte
            if byte_in_line < 8:
                edit_col = 10 + byte_in_line * 3
            else:
                edit_col = 10 + byte_in_line * 3 + 1
            entry_width = 20
            width_chars = 3
        else:  # ascii mode
            # Calculate position for ASCII character
            edit_col = 61 + byte_in_line
            entry_width = 12
            width_chars = 2
        
        # Get the bounding box for the text position
        bbox = self.text_widget.bbox(f"{line}.{edit_col}")
        if not bbox:
            return
        
        x, y, width, height = bbox
        
        # Create entry widget for editing
        self.edit_entry = tk.Entry(self.text_widget, width=width_chars, font=("Courier", 10))
        self.edit_entry.place(x=x, y=y, width=entry_width, height=height)
        
        # Set current value
        if edit_mode == 'hex':
            current_value = f"{self.data[offset]:02X}"
        else:  # ascii mode
            byte_val = self.data[offset]
            if 32 <= byte_val <= 126:
                current_value = chr(byte_val)
            else:
                current_value = "."
        
        self.edit_entry.insert(0, current_value)
        self.edit_entry.select_range(0, tk.END)
        self.edit_entry.focus()
        
        # Bind events
        self.edit_entry.bind("<Return>", self.finish_editing)
        self.edit_entry.bind("<Escape>", lambda e: self.close_editor())
        self.edit_entry.bind("<FocusOut>", lambda e: self.close_editor())
        
        # Use KeyPress for key repeat support (holding keys down)
        if edit_mode == 'hex':
            self.edit_entry.bind("<KeyPress>", self.on_hex_keypress)
        else:
            self.edit_entry.bind("<KeyPress>", self.on_ascii_keypress)
        
        # Highlight the byte being edited
        if edit_mode == 'hex':
            self.text_widget.tag_add("editing", f"{line}.{edit_col}", f"{line}.{edit_col+2}")
        else:
            self.text_widget.tag_add("editing", f"{line}.{edit_col}", f"{line}.{edit_col+1}")
    
    def on_hex_keypress(self, event):
        """Handle hex editing with key repeat support"""
        if not self.edit_entry or self.editing_offset is None:
            return
        
        # Let special keys pass through normally
        if event.keysym in ['Escape', 'Return', 'BackSpace', 'Delete', 'Left', 'Right', 'Tab', 'Shift_L', 'Shift_R', 'Control_L', 'Control_R', 'Alt_L', 'Alt_R']:
            return
        
        # Get the character being typed
        char = event.char.upper()
        
        # Only process valid hex characters
        if char not in '0123456789ABCDEF':
            return "break"  # Block non-hex characters
        
        # Get current value and add the new character
        current_value = self.edit_entry.get().strip().upper()
        new_value = current_value + char
        
        # Limit to 2 characters
        if len(new_value) > 2:
            new_value = char  # Start fresh with just the new character
        
        # Update entry
        self.edit_entry.delete(0, tk.END)
        self.edit_entry.insert(0, new_value)
        
        # Auto-advance when 2 hex digits are entered
        if len(new_value) == 2:
            try:
                byte_value = int(new_value, 16)
                current_offset = self.editing_offset
                
                # Update the current byte immediately
                self.data[current_offset] = byte_value
                self.modified = True
                
                # Update window title
                title = "Hex Editor"
                if self.current_file:
                    title += f" - {os.path.basename(self.current_file)}"
                if self.modified:
                    title += " *"
                self.root.title(title)
                
                # Move to next byte
                next_offset = current_offset + 1
                if next_offset < len(self.data):
                    line = (next_offset // 16) + 1
                    byte_in_line = next_offset % 16
                    if byte_in_line < 8:
                        col = 10 + byte_in_line * 3
                    else:
                        col = 10 + byte_in_line * 3 + 1
                    
                    self.editing_offset = next_offset
                    self.edit_entry.delete(0, tk.END)
                    self.update_single_byte_display(current_offset)
                    
                    bbox = self.text_widget.bbox(f"{line}.{col}")
                    if bbox:
                        x, y, width, height = bbox
                        self.edit_entry.place(x=x, y=y)
                        self.edit_entry.focus()
                    
                    self.update_status(f"Updated 0x{current_offset:08X} = 0x{byte_value:02X}")
                else:
                    self.display_hex()
                    self.close_editor()
                    self.update_status(f"Updated 0x{current_offset:08X} = 0x{byte_value:02X}")
            except ValueError:
                pass
        
        return "break"  # Prevent default entry behavior
    
    def on_ascii_keypress(self, event):
        """Handle ASCII editing with key repeat support"""
        if not self.edit_entry or self.editing_offset is None:
            return
        
        # Let special keys pass through normally
        if event.keysym in ['Escape', 'Return', 'BackSpace', 'Delete', 'Left', 'Right', 'Tab', 'Shift_L', 'Shift_R', 'Control_L', 'Control_R', 'Alt_L', 'Alt_R']:
            return
        
        # Get the character being typed
        char = event.char
        
        # Only process printable characters
        if not char or len(char) != 1 or ord(char) < 32:
            return "break"
        
        current_offset = self.editing_offset
        byte_value = ord(char)
        
        # Update the current byte immediately
        self.data[current_offset] = byte_value
        self.modified = True
        
        # Update window title
        title = "Hex Editor"
        if self.current_file:
            title += f" - {os.path.basename(self.current_file)}"
        if self.modified:
            title += " *"
        self.root.title(title)
        
        # Update display for this byte
        self.update_single_byte_display(current_offset)
        
        # Move to next byte
        next_offset = current_offset + 1
        if next_offset < len(self.data):
            line = (next_offset // 16) + 1
            byte_in_line = next_offset % 16
            col = 61 + byte_in_line
            
            self.editing_offset = next_offset
            self.edit_entry.delete(0, tk.END)
            
            bbox = self.text_widget.bbox(f"{line}.{col}")
            if bbox:
                x, y, width, height = bbox
                self.edit_entry.place(x=x, y=y)
                self.edit_entry.focus()
            
            self.update_status(f"Updated 0x{current_offset:08X} = '{char}' (0x{byte_value:02X})")
        else:
            self.display_hex()
            self.close_editor()
            self.update_status(f"Updated 0x{current_offset:08X} = '{char}' (0x{byte_value:02X})")
        
        return "break"  # Prevent default entry behavior)
    
    def finish_editing(self, event=None):
        if self.edit_entry and self.editing_offset is not None:
            if self.edit_mode == 'hex':
                new_value = self.edit_entry.get().strip().upper()
                
                # Validate hex input
                if len(new_value) == 0:
                    self.close_editor()
                    return
                
                try:
                    # Allow 1 or 2 hex digits
                    if len(new_value) > 2:
                        raise ValueError("Too many digits")
                    
                    byte_value = int(new_value, 16)
                    
                    if 0 <= byte_value <= 255:
                        # Update the data
                        self.data[self.editing_offset] = byte_value
                        self.modified = True
                        
                        # Update display
                        self.display_hex()
                        
                        # Update window title to show modified state
                        title = "Hex Editor"
                        if self.current_file:
                            title += f" - {os.path.basename(self.current_file)}"
                        if self.modified:
                            title += " *"
                        self.root.title(title)
                        
                        self.update_status(f"Updated offset 0x{self.editing_offset:08X} to 0x{byte_value:02X}")
                    else:
                        messagebox.showerror("Error", "Value must be between 00 and FF")
                except ValueError:
                    messagebox.showerror("Error", "Invalid hex value")
            else:  # ascii mode
                new_value = self.edit_entry.get()
                
                if len(new_value) == 0:
                    self.close_editor()
                    return
                
                # Take only the first character
                char = new_value[0]
                byte_value = ord(char)
                
                # Update the data
                self.data[self.editing_offset] = byte_value
                self.modified = True
                
                # Update display
                self.display_hex()
                
                # Update window title to show modified state
                title = "Hex Editor"
                if self.current_file:
                    title += f" - {os.path.basename(self.current_file)}"
                if self.modified:
                    title += " *"
                self.root.title(title)
                
                self.update_status(f"Updated offset 0x{self.editing_offset:08X} to '{char}' (0x{byte_value:02X})")
        
        self.close_editor()
    
    def close_editor(self):
        if self.edit_entry:
            self.edit_entry.destroy()
            self.edit_entry = None
        
        self.editing_offset = None
        self.text_widget.tag_remove("editing", 1.0, tk.END)
        self.text_widget.focus()
    
    def on_key_press(self, event):
        # Prevent direct text editing
        if event.char and not event.state & 0x4:  # Not Ctrl key
            return "break"
    
    def show_find_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Find")
        dialog.geometry("400x120")
        dialog.transient(self.root)
        dialog.grab_set()
        
        tk.Label(dialog, text="Find (hex):").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        entry = tk.Entry(dialog, width=40)
        entry.grid(row=0, column=1, padx=5, pady=5)
        entry.focus()
        
        result_label = tk.Label(dialog, text="")
        result_label.grid(row=1, column=0, columnspan=2, padx=5, pady=5)
        
        def do_find():
            search_hex = entry.get().strip().replace(" ", "")
            if not search_hex:
                return
            
            try:
                search_bytes = bytes.fromhex(search_hex)
                offset = self.data.find(search_bytes)
                
                if offset != -1:
                    result_label.config(text=f"Found at offset: 0x{offset:08X} ({offset})", fg="green")
                    self.highlight_offset(offset, len(search_bytes))
                else:
                    result_label.config(text="Not found", fg="red")
            except ValueError:
                result_label.config(text="Invalid hex string", fg="red")
        
        tk.Button(dialog, text="Find", command=do_find).grid(row=2, column=0, columnspan=2, pady=10)
        
        entry.bind("<Return>", lambda e: do_find())
    
    def show_goto_dialog(self):
        dialog = tk.Toplevel(self.root)
        dialog.title("Go to Offset")
        dialog.geometry("300x100")
        dialog.transient(self.root)
        dialog.grab_set()
        
        tk.Label(dialog, text="Offset (hex):").grid(row=0, column=0, padx=5, pady=5, sticky=tk.W)
        entry = tk.Entry(dialog, width=20)
        entry.grid(row=0, column=1, padx=5, pady=5)
        entry.focus()
        
        def do_goto():
            offset_str = entry.get().strip()
            if not offset_str:
                return
            
            try:
                # Remove 0x prefix if present
                if offset_str.startswith("0x") or offset_str.startswith("0X"):
                    offset_str = offset_str[2:]
                
                offset = int(offset_str, 16)
                
                if 0 <= offset < len(self.data):
                    self.highlight_offset(offset, 1)
                    dialog.destroy()
                else:
                    messagebox.showerror("Error", f"Offset out of range (0-0x{len(self.data)-1:X})")
            except ValueError:
                messagebox.showerror("Error", "Invalid hex offset")
        
        tk.Button(dialog, text="Go", command=do_goto).grid(row=1, column=0, columnspan=2, pady=10)
        
        entry.bind("<Return>", lambda e: do_goto())
    
    def highlight_offset(self, offset, length=1):
        # Clear previous highlights
        self.text_widget.tag_remove("highlight", 1.0, tk.END)
        
        # Calculate line and position
        line = (offset // 16) + 1
        byte_in_line = offset % 16
        
        # Calculate column positions for hex area
        if byte_in_line < 8:
            start_col = 10 + byte_in_line * 3
        else:
            start_col = 10 + byte_in_line * 3 + 1  # Extra space after 8th byte
        
        # Highlight the byte(s)
        for i in range(length):
            current_offset = offset + i
            current_line = (current_offset // 16) + 1
            current_byte_in_line = current_offset % 16
            
            if current_byte_in_line < 8:
                col = 10 + current_byte_in_line * 3
            else:
                col = 10 + current_byte_in_line * 3 + 1
            
            # Highlight hex value
            self.text_widget.tag_add("highlight", f"{current_line}.{col}", f"{current_line}.{col+2}")
            
            # Highlight ASCII character
            ascii_col = 61 + current_byte_in_line
            self.text_widget.tag_add("highlight", f"{current_line}.{ascii_col}", f"{current_line}.{ascii_col+1}")
        
        # Scroll to the line
        self.text_widget.see(f"{line}.0")
    
    def auto_detect_encoding(self):
        """Automatically detect the best encoding for the file"""
        if not self.data or len(self.data) == 0:
            self.current_encoding = 'ASCII'
            self.encoding_var.set('ASCII')
            return
        
        # Sample the file (first 10KB or entire file if smaller)
        sample_size = min(10000, len(self.data))
        sample = bytes(self.data[:sample_size])
        
        # Check for BOM (Byte Order Mark)
        if sample.startswith(b'\xff\xfe\x00\x00'):
            self.current_encoding = 'UTF-32LE'
            self.encoding_var.set('UTF-32LE')
            return
        elif sample.startswith(b'\x00\x00\xfe\xff'):
            self.current_encoding = 'UTF-32BE'
            self.encoding_var.set('UTF-32BE')
            return
        elif sample.startswith(b'\xff\xfe'):
            self.current_encoding = 'UTF-16LE'
            self.encoding_var.set('UTF-16LE')
            return
        elif sample.startswith(b'\xfe\xff'):
            self.current_encoding = 'UTF-16BE'
            self.encoding_var.set('UTF-16BE')
            return
        elif sample.startswith(b'\xef\xbb\xbf'):
            self.current_encoding = 'UTF-8'
            self.encoding_var.set('UTF-8')
            return
        
        # Count characteristics
        null_bytes = sample.count(b'\x00')
        high_bytes = sum(1 for b in sample if b > 127)
        printable_ascii = sum(1 for b in sample if 32 <= b <= 126 or b in (9, 10, 13))
        
        # If lots of null bytes, likely UTF-16 or UTF-32
        null_ratio = null_bytes / len(sample)
        if null_ratio > 0.3:
            # Check for UTF-16LE pattern (every other byte is null)
            even_nulls = sum(1 for i in range(0, len(sample)-1, 2) if sample[i+1] == 0)
            odd_nulls = sum(1 for i in range(1, len(sample)-1, 2) if sample[i] == 0)
            
            if even_nulls > odd_nulls and even_nulls > len(sample) / 4:
                self.current_encoding = 'UTF-16LE'
                self.encoding_var.set('UTF-16LE')
                return
            elif odd_nulls > even_nulls and odd_nulls > len(sample) / 4:
                self.current_encoding = 'UTF-16BE'
                self.encoding_var.set('UTF-16BE')
                return
        
        # If mostly printable ASCII, use ASCII
        if printable_ascii / len(sample) > 0.9:
            self.current_encoding = 'ASCII'
            self.encoding_var.set('ASCII')
            return
        
        # Try UTF-8 validation
        if high_bytes > 0:
            try:
                sample.decode('utf-8')
                # Valid UTF-8
                self.current_encoding = 'UTF-8'
                self.encoding_var.set('UTF-8')
                return
            except UnicodeDecodeError:
                pass
        
        # Check for Windows CP1252 indicators (common in Windows executables)
        cp1252_chars = sum(1 for b in sample if b in range(0x80, 0x9F))
        if cp1252_chars > 0:
            self.current_encoding = 'CP1252'
            self.encoding_var.set('CP1252')
            return
        
        # Default to Latin-1 for binary files with high bytes
        if high_bytes > len(sample) * 0.1:
            self.current_encoding = 'Latin-1'
            self.encoding_var.set('Latin-1')
        else:
            self.current_encoding = 'ASCII'
            self.encoding_var.set('ASCII')
    
    def on_encoding_change(self, event=None):
        self.current_encoding = self.encoding_var.get()
        self.close_editor()
        self.display_hex()
        self.update_status(f"Encoding changed to {self.current_encoding}")
    
    def get_text_representation(self, chunk):
        """Convert a chunk of bytes to text based on current encoding"""
        if self.current_encoding == 'ASCII':
            text = ""
            for byte in chunk:
                if 32 <= byte <= 126:
                    text += chr(byte)
                else:
                    text += "."
            return text.ljust(16)  # Pad to 16 chars
        
        elif self.current_encoding == 'Latin-1' or self.current_encoding == 'CP1252':
            encoding = 'latin-1' if self.current_encoding == 'Latin-1' else 'cp1252'
            text = ""
            for byte in chunk:
                if 32 <= byte <= 126 or byte >= 160:
                    text += bytes([byte]).decode(encoding, errors='replace')
                else:
                    text += "."
            return text.ljust(16)
        
        elif self.current_encoding == 'UTF-8':
            # For UTF-8, show valid characters, dots for invalid
            text = ""
            i = 0
            while i < len(chunk):
                byte = chunk[i]
                # Try to decode UTF-8 sequence
                if byte < 128:
                    text += chr(byte) if 32 <= byte <= 126 else "."
                    i += 1
                else:
                    # Multi-byte sequence
                    decoded = False
                    for length in range(2, 5):
                        if i + length <= len(chunk):
                            try:
                                char = bytes(chunk[i:i+length]).decode('utf-8')
                                text += char
                                i += length
                                decoded = True
                                break
                            except:
                                pass
                    if not decoded:
                        text += "."
                        i += 1
            return text.ljust(16)
        
        elif self.current_encoding == 'UTF-16LE':
            # UTF-16 Little Endian - 2 bytes per character
            text = ""
            for i in range(0, len(chunk), 2):
                if i + 1 < len(chunk):
                    try:
                        char = bytes([chunk[i], chunk[i+1]]).decode('utf-16-le')
                        if char.isprintable():
                            text += char
                        else:
                            text += "."
                    except:
                        text += "."
                else:
                    text += "."
            return text.ljust(8)  # 8 chars for 16 bytes
        
        elif self.current_encoding == 'UTF-16BE':
            # UTF-16 Big Endian - 2 bytes per character
            text = ""
            for i in range(0, len(chunk), 2):
                if i + 1 < len(chunk):
                    try:
                        char = bytes([chunk[i], chunk[i+1]]).decode('utf-16-be')
                        if char.isprintable():
                            text += char
                        else:
                            text += "."
                    except:
                        text += "."
                else:
                    text += "."
            return text.ljust(8)  # 8 chars for 16 bytes
        
        elif self.current_encoding == 'UTF-32LE':
            # UTF-32 Little Endian - 4 bytes per character
            text = ""
            for i in range(0, len(chunk), 4):
                if i + 3 < len(chunk):
                    try:
                        char = bytes([chunk[i], chunk[i+1], chunk[i+2], chunk[i+3]]).decode('utf-32-le')
                        if char.isprintable():
                            text += char
                        else:
                            text += "."
                    except:
                        text += "."
                else:
                    text += "."
            return text.ljust(4)  # 4 chars for 16 bytes
        
        elif self.current_encoding == 'UTF-32BE':
            # UTF-32 Big Endian - 4 bytes per character
            text = ""
            for i in range(0, len(chunk), 4):
                if i + 3 < len(chunk):
                    try:
                        char = bytes([chunk[i], chunk[i+1], chunk[i+2], chunk[i+3]]).decode('utf-32-be')
                        if char.isprintable():
                            text += char
                        else:
                            text += "."
                    except:
                        text += "."
                else:
                    text += "."
            return text.ljust(4)  # 4 chars for 16 bytes
        
        elif self.current_encoding == 'CP437 (DOS)':
            # DOS/OEM code page - common in older executables
            text = ""
            for byte in chunk:
                try:
                    char = bytes([byte]).decode('cp437')
                    if char.isprintable() or byte >= 128:
                        text += char
                    else:
                        text += "."
                except:
                    text += "."
            return text.ljust(16)
        
        elif self.current_encoding == 'CP850 (DOS)':
            # DOS Latin-1 code page
            text = ""
            for byte in chunk:
                try:
                    char = bytes([byte]).decode('cp850')
                    if char.isprintable() or byte >= 128:
                        text += char
                    else:
                        text += "."
                except:
                    text += "."
            return text.ljust(16)
        
        elif self.current_encoding == 'CP866 (DOS Cyrillic)':
            # DOS Cyrillic - common in Russian software
            text = ""
            for byte in chunk:
                try:
                    char = bytes([byte]).decode('cp866')
                    if char.isprintable() or byte >= 128:
                        text += char
                    else:
                        text += "."
                except:
                    text += "."
            return text.ljust(16)
        
        elif self.current_encoding == 'Shift-JIS':
            # Japanese encoding - common in Japanese software
            text = ""
            i = 0
            while i < len(chunk):
                byte = chunk[i]
                if byte < 128:
                    text += chr(byte) if 32 <= byte <= 126 else "."
                    i += 1
                else:
                    # Try 2-byte sequence
                    if i + 1 < len(chunk):
                        try:
                            char = bytes([chunk[i], chunk[i+1]]).decode('shift-jis')
                            text += char
                            i += 2
                        except:
                            text += "."
                            i += 1
                    else:
                        text += "."
                        i += 1
            return text.ljust(16)
        
        elif self.current_encoding == 'GB2312 (Chinese)':
            # Simplified Chinese encoding
            text = ""
            i = 0
            while i < len(chunk):
                byte = chunk[i]
                if byte < 128:
                    text += chr(byte) if 32 <= byte <= 126 else "."
                    i += 1
                else:
                    if i + 1 < len(chunk):
                        try:
                            char = bytes([chunk[i], chunk[i+1]]).decode('gb2312')
                            text += char
                            i += 2
                        except:
                            text += "."
                            i += 1
                    else:
                        text += "."
                        i += 1
            return text.ljust(16)
        
        elif self.current_encoding == 'EUC-KR (Korean)':
            # Korean encoding
            text = ""
            i = 0
            while i < len(chunk):
                byte = chunk[i]
                if byte < 128:
                    text += chr(byte) if 32 <= byte <= 126 else "."
                    i += 1
                else:
                    if i + 1 < len(chunk):
                        try:
                            char = bytes([chunk[i], chunk[i+1]]).decode('euc-kr')
                            text += char
                            i += 2
                        except:
                            text += "."
                            i += 1
                    else:
                        text += "."
                        i += 1
            return text.ljust(16)
        
        elif self.current_encoding == 'ISO-8859-1':
            # Western European - same as Latin-1 but explicit
            text = ""
            for byte in chunk:
                if 32 <= byte <= 126 or byte >= 160:
                    text += bytes([byte]).decode('iso-8859-1', errors='replace')
                else:
                    text += "."
            return text.ljust(16)
        
        elif self.current_encoding == 'ISO-8859-15':
            # Latin-9 with Euro symbol
            text = ""
            for byte in chunk:
                if 32 <= byte <= 126 or byte >= 160:
                    text += bytes([byte]).decode('iso-8859-15', errors='replace')
                else:
                    text += "."
            return text.ljust(16)
        
        elif self.current_encoding == 'KOI8-R (Russian)':
            # Russian encoding - common in Russian executables
            text = ""
            for byte in chunk:
                try:
                    char = bytes([byte]).decode('koi8-r')
                    if char.isprintable():
                        text += char
                    else:
                        text += "."
                except:
                    text += "."
            return text.ljust(16)
        
        elif self.current_encoding == 'Base64':
            # Show Base64 representation (useful for encoded payloads)
            import base64
            try:
                encoded = base64.b64encode(bytes(chunk)).decode('ascii')
                return encoded[:16].ljust(16)
            except:
                return "." * 16
        
        elif self.current_encoding == 'Hex Escaped':
            # Show as escaped hex (\x00 format) - common in shellcode
            text = ""
            for byte in chunk[:5]:  # Only show first 5 bytes due to space
                text += f"\\x{byte:02x}"
            return text.ljust(16)
        
        elif self.current_encoding == 'ROT13':
            # ROT13 decoding - simple obfuscation often used
            text = ""
            for byte in chunk:
                if 65 <= byte <= 90:  # A-Z
                    text += chr(((byte - 65 + 13) % 26) + 65)
                elif 97 <= byte <= 122:  # a-z
                    text += chr(((byte - 97 + 13) % 26) + 97)
                elif 32 <= byte <= 126:
                    text += chr(byte)
                else:
                    text += "."
            return text.ljust(16)
        
        return "".ljust(16)
    
    def update_single_byte_display(self, offset, highlight_change=True):
        """Update just a single byte in the display without refreshing everything"""
        if offset >= len(self.data):
            return
        
        line = (offset // 16) + 1
        byte_in_line = offset % 16
        
        # Calculate hex position
        if byte_in_line < 8:
            hex_col = 10 + byte_in_line * 3
        else:
            hex_col = 10 + byte_in_line * 3 + 1
        
        # Calculate ASCII position
        ascii_col = 61 + byte_in_line
        
        # Get the byte value
        byte_val = self.data[offset]
        
        # Update hex value
        self.text_widget.delete(f"{line}.{hex_col}", f"{line}.{hex_col+2}")
        self.text_widget.insert(f"{line}.{hex_col}", f"{byte_val:02X}")
        
        # Update text value (simplified - just update the whole line for encodings)
        # Get the full line's bytes for proper encoding
        line_start = (line - 1) * 16
        line_end = min(line_start + 16, len(self.data))
        chunk = self.data[line_start:line_end]
        
        # Regenerate the text representation
        text_part = self.get_text_representation(chunk)
        
        # Update just the text portion
        self.text_widget.delete(f"{line}.61", f"{line}.end")
        self.text_widget.insert(f"{line}.61", text_part)
        
        # Reapply syntax highlighting for this line
        self.text_widget.tag_add("offset", f"{line}.0", f"{line}.10")
        self.text_widget.tag_add("hex", f"{line}.10", f"{line}.60")
        self.text_widget.tag_add("ascii", f"{line}.61", f"{line}.end")
        
        # Add temporary change highlighting
        if highlight_change:
            self.highlight_change(line, hex_col, ascii_col)
    
    def highlight_change(self, line, hex_col, ascii_col):
        """Temporarily highlight a changed byte in both hex and ASCII views"""
        # Define the positions to highlight
        hex_start = f"{line}.{hex_col}"
        hex_end = f"{line}.{hex_col + 2}"
        ascii_start = f"{line}.{ascii_col}"
        ascii_end = f"{line}.{ascii_col + 1}"
        
        # Add the highlight tags (will override other tags visually)
        self.text_widget.tag_add("changed_hex", hex_start, hex_end)
        self.text_widget.tag_add("changed_ascii", ascii_start, ascii_end)
        
        # Raise the priority of changed tags so they show on top
        self.text_widget.tag_raise("changed_hex")
        self.text_widget.tag_raise("changed_ascii")
        
        # Schedule removal of the highlight after 1.5 seconds
        def remove_highlight():
            try:
                self.text_widget.tag_remove("changed_hex", hex_start, hex_end)
                self.text_widget.tag_remove("changed_ascii", ascii_start, ascii_end)
            except tk.TclError:
                pass  # Widget might be destroyed
        
        self.root.after(1500, remove_highlight)
    
    def highlight_changes(self, offset, length):
        """Temporarily highlight multiple changed bytes in both hex and ASCII views"""
        positions = []
        
        for i in range(length):
            current_offset = offset + i
            if current_offset >= len(self.data):
                break
                
            line = (current_offset // 16) + 1
            byte_in_line = current_offset % 16
            
            # Calculate hex position
            if byte_in_line < 8:
                hex_col = 10 + byte_in_line * 3
            else:
                hex_col = 10 + byte_in_line * 3 + 1
            
            # Calculate ASCII position
            ascii_col = 61 + byte_in_line
            
            hex_start = f"{line}.{hex_col}"
            hex_end = f"{line}.{hex_col + 2}"
            ascii_start = f"{line}.{ascii_col}"
            ascii_end = f"{line}.{ascii_col + 1}"
            
            # Add the highlight tags
            self.text_widget.tag_add("changed_hex", hex_start, hex_end)
            self.text_widget.tag_add("changed_ascii", ascii_start, ascii_end)
            
            positions.append((hex_start, hex_end, ascii_start, ascii_end))
        
        # Raise the priority of changed tags
        self.text_widget.tag_raise("changed_hex")
        self.text_widget.tag_raise("changed_ascii")
        
        # Scroll to show the first changed byte
        if positions:
            first_line = int(positions[0][0].split('.')[0])
            self.text_widget.see(f"{first_line}.0")
        
        # Schedule removal of all highlights after 2 seconds
        def remove_highlights():
            try:
                for hex_start, hex_end, ascii_start, ascii_end in positions:
                    self.text_widget.tag_remove("changed_hex", hex_start, hex_end)
                    self.text_widget.tag_remove("changed_ascii", ascii_start, ascii_end)
            except tk.TclError:
                pass  # Widget might be destroyed
        
        self.root.after(2000, remove_highlights)
    
    def is_pe_file(self):
        """Check if the loaded file is a valid PE (Portable Executable) file"""
        if len(self.data) < 64:
            return False
        
        # Check for MZ signature
        if self.data[0:2] != b'MZ':
            return False
        
        # Get PE header offset
        pe_offset = struct.unpack('<I', self.data[60:64])[0]
        
        if pe_offset + 4 > len(self.data):
            return False
        
        # Check for PE signature
        if self.data[pe_offset:pe_offset+4] != b'PE\x00\x00':
            return False
        
        return True
    
    def is_elf_file(self):
        """Check if the loaded file is a valid ELF (Linux/Unix) executable"""
        if len(self.data) < 4:
            return False
        return self.data[:4] == b'\x7fELF'
    
    def is_executable_file(self, filepath):
        """Check if file has executable permissions (Linux/Unix)"""
        if IS_WINDOWS:
            return False
        try:
            return os.access(filepath, os.X_OK)
        except:
            return False
    
    def show_pe_info(self):
        """Display PE file information in a dialog"""
        if not self.data:
            messagebox.showinfo("No File", "Please open a file first")
            return
        
        if not self.is_pe_file():
            messagebox.showinfo("Not a PE File", "This file is not a valid PE (EXE/DLL) file")
            return
        
        try:
            info = self.parse_pe_info()
            
            # Create info dialog
            dialog = tk.Toplevel(self.root)
            dialog.title("PE File Information")
            dialog.geometry("700x600")
            dialog.transient(self.root)
            
            # Create text widget with scrollbar
            frame = tk.Frame(dialog)
            frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            scrollbar = tk.Scrollbar(frame)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            
            text = tk.Text(frame, wrap=tk.WORD, font=("Courier", 10), yscrollcommand=scrollbar.set)
            text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            scrollbar.config(command=text.yview)
            
            # Display info
            text.insert(1.0, info)
            text.config(state=tk.DISABLED)
            
            # Add close button
            tk.Button(dialog, text="Close", command=dialog.destroy).pack(pady=5)
            
        except Exception as e:
            messagebox.showerror("Error", f"Error parsing PE file:\n{str(e)}")
    
    def parse_pe_sections(self):
        """Parse PE sections and store them for sidebar display"""
        self.pe_sections = []
        
        try:
            pe_offset = struct.unpack('<I', self.data[60:64])[0]
            coff_offset = pe_offset + 4
            num_sections = struct.unpack('<H', self.data[coff_offset+2:coff_offset+4])[0]
            opt_header_size = struct.unpack('<H', self.data[coff_offset+16:coff_offset+18])[0]
            section_offset = coff_offset + 20 + opt_header_size
            
            # Add DOS Header
            self.pe_sections.append({
                'name': 'DOS Header',
                'offset': 0,
                'size': pe_offset
            })
            
            # Add PE Header
            self.pe_sections.append({
                'name': 'PE Header',
                'offset': pe_offset,
                'size': section_offset - pe_offset
            })
            
            # Parse sections
            for i in range(num_sections):
                sect_start = section_offset + (i * 40)
                if sect_start + 40 > len(self.data):
                    break
                
                name = self.data[sect_start:sect_start+8].decode('ascii', errors='ignore').rstrip('\x00')
                raw_ptr = struct.unpack('<I', self.data[sect_start+20:sect_start+24])[0]
                raw_size = struct.unpack('<I', self.data[sect_start+16:sect_start+20])[0]
                
                self.pe_sections.append({
                    'name': name if name else f'Section {i+1}',
                    'offset': raw_ptr,
                    'size': raw_size
                })
        except:
            self.pe_sections = []
    
    def show_pe_sidebar(self):
        """Display the PE sections sidebar"""
        # Clear existing buttons
        for widget in self.sections_scrollable.winfo_children():
            widget.destroy()
        
        # Create buttons for each section
        for section in self.pe_sections:
            btn_frame = tk.Frame(self.sections_scrollable, bg="white")
            btn_frame.pack(fill=tk.X, padx=5, pady=2)
            
            btn = tk.Button(btn_frame, text=section['name'], 
                          command=lambda s=section: self.jump_to_section(s),
                          bg="#f0f0f0", relief=tk.RAISED, anchor=tk.W,
                          font=("Arial", 9))
            btn.pack(fill=tk.X)
            
            # Add offset label
            offset_label = tk.Label(btn_frame, text=f"0x{section['offset']:X}",
                                   font=("Courier", 8), fg="#666666", bg="white")
            offset_label.pack()
        
        # Show the sidebar
        self.sidebar_frame.pack(side=tk.LEFT, fill=tk.Y, padx=(0, 5))
    
    def hide_pe_sidebar(self):
        """Hide the PE sections sidebar"""
        self.sidebar_frame.pack_forget()
        self.pe_sections = []
    
    def jump_to_section(self, section):
        """Jump to a specific PE section"""
        self.close_editor()
        offset = section['offset']
        if offset < len(self.data):
            self.highlight_offset(offset, min(16, section['size']))
            self.update_status(f"Jumped to {section['name']} at offset 0x{offset:08X} (Size: {section['size']} bytes)")
    
    def parse_pe_info(self):
        """Parse PE file structure and return formatted information"""
        info = []
        
        # DOS Header
        info.append("=== DOS HEADER ===")
        info.append(f"Signature: {self.data[0:2].decode('ascii', errors='ignore')}")
        
        pe_offset = struct.unpack('<I', self.data[60:64])[0]
        info.append(f"PE Header Offset: 0x{pe_offset:08X}\n")
        
        # PE Header
        info.append("=== PE HEADER ===")
        pe_sig = self.data[pe_offset:pe_offset+4]
        info.append(f"Signature: {pe_sig}")
        
        # COFF Header
        coff_offset = pe_offset + 4
        machine = struct.unpack('<H', self.data[coff_offset:coff_offset+2])[0]
        num_sections = struct.unpack('<H', self.data[coff_offset+2:coff_offset+4])[0]
        timestamp = struct.unpack('<I', self.data[coff_offset+4:coff_offset+8])[0]
        
        machine_types = {
            0x014c: "i386 (x86)",
            0x0200: "Intel Itanium",
            0x8664: "x64 (AMD64)",
            0xAA64: "ARM64",
            0x01c0: "ARM"
        }
        
        info.append(f"Machine: 0x{machine:04X} ({machine_types.get(machine, 'Unknown')})")
        info.append(f"Number of Sections: {num_sections}")
        info.append(f"Timestamp: 0x{timestamp:08X}")
        
        # Optional Header
        opt_offset = coff_offset + 20
        magic = struct.unpack('<H', self.data[opt_offset:opt_offset+2])[0]
        
        info.append(f"\n=== OPTIONAL HEADER ===")
        if magic == 0x10b:
            info.append("Format: PE32")
            is_pe32_plus = False
        elif magic == 0x20b:
            info.append("Format: PE32+ (64-bit)")
            is_pe32_plus = True
        else:
            info.append(f"Format: Unknown (0x{magic:04X})")
            is_pe32_plus = False
        
        if is_pe32_plus:
            entry_point = struct.unpack('<I', self.data[opt_offset+16:opt_offset+20])[0]
            image_base = struct.unpack('<Q', self.data[opt_offset+24:opt_offset+32])[0]
        else:
            entry_point = struct.unpack('<I', self.data[opt_offset+16:opt_offset+20])[0]
            image_base = struct.unpack('<I', self.data[opt_offset+28:opt_offset+32])[0]
        
        info.append(f"Entry Point: 0x{entry_point:08X}")
        info.append(f"Image Base: 0x{image_base:X}")
        
        # Subsystem
        if is_pe32_plus:
            subsystem = struct.unpack('<H', self.data[opt_offset+68:opt_offset+70])[0]
        else:
            subsystem = struct.unpack('<H', self.data[opt_offset+68:opt_offset+70])[0]
        
        subsystem_types = {
            1: "Native",
            2: "Windows GUI",
            3: "Windows Console",
            5: "OS/2 Console",
            7: "POSIX Console",
            9: "Windows CE",
            10: "EFI Application",
            11: "EFI Boot Service Driver",
            12: "EFI Runtime Driver"
        }
        
        info.append(f"Subsystem: {subsystem_types.get(subsystem, f'Unknown ({subsystem})')}")
        
        # Sections
        info.append(f"\n=== SECTIONS ({num_sections}) ===")
        
        opt_header_size = struct.unpack('<H', self.data[coff_offset+16:coff_offset+18])[0]
        section_offset = coff_offset + 20 + opt_header_size
        
        for i in range(num_sections):
            sect_start = section_offset + (i * 40)
            if sect_start + 40 > len(self.data):
                break
            
            name = self.data[sect_start:sect_start+8].decode('ascii', errors='ignore').rstrip('\x00')
            virtual_size = struct.unpack('<I', self.data[sect_start+8:sect_start+12])[0]
            virtual_addr = struct.unpack('<I', self.data[sect_start+12:sect_start+16])[0]
            raw_size = struct.unpack('<I', self.data[sect_start+16:sect_start+20])[0]
            raw_ptr = struct.unpack('<I', self.data[sect_start+20:sect_start+24])[0]
            
            info.append(f"\n[{i+1}] {name}")
            info.append(f"  Virtual Address: 0x{virtual_addr:08X}")
            info.append(f"  Virtual Size: {virtual_size} bytes (0x{virtual_size:X})")
            info.append(f"  Raw Address: 0x{raw_ptr:08X}")
            info.append(f"  Raw Size: {raw_size} bytes (0x{raw_size:X})")
        
        return "\n".join(info)
    
    def show_metadata_editor(self):
        """Show dialog to edit PE file metadata"""
        if not self.data:
            messagebox.showinfo("No File", "Please open a file first")
            return
        
        if not self.is_pe_file():
            messagebox.showinfo("Not a PE File", "This file is not a valid PE (EXE/DLL) file")
            return
        
        # Create metadata editor dialog
        dialog = tk.Toplevel(self.root)
        dialog.title("Edit Program Metadata")
        dialog.geometry("650x550")
        dialog.transient(self.root)
        
        # Extract current metadata
        metadata = self.extract_version_info()
        
        tk.Label(dialog, text="Program Metadata Editor", font=("Arial", 12, "bold")).pack(pady=10)
        tk.Label(dialog, text="Edit the metadata fields below:", font=("Arial", 9)).pack()
        
        # Create scrollable frame for fields
        canvas = tk.Canvas(dialog)
        scrollbar = tk.Scrollbar(dialog, orient="vertical", command=canvas.yview)
        scrollable_frame = tk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Metadata fields
        fields = [
            ("CompanyName", "Company Name"),
            ("FileDescription", "File Description"),
            ("FileVersion", "File Version"),
            ("InternalName", "Internal Name"),
            ("LegalCopyright", "Copyright"),
            ("LegalTrademarks", "Trademarks"),
            ("OriginalFilename", "Original Filename"),
            ("ProductName", "Product Name"),
            ("ProductVersion", "Product Version"),
        ]
        
        entries = {}
        
        for key, label in fields:
            frame = tk.Frame(scrollable_frame)
            frame.pack(fill=tk.X, padx=20, pady=5)
            
            tk.Label(frame, text=label + ":", width=20, anchor=tk.W).pack(side=tk.LEFT)
            entry = tk.Entry(frame, width=50)
            entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
            
            # Set current value if exists
            if key in metadata:
                entry.insert(0, metadata[key])
            
            entries[key] = entry
        
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=10, pady=10)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y, pady=10)
        
        # Status label
        status_label = tk.Label(dialog, text="", fg="blue")
        status_label.pack(pady=5)
        
        # Buttons
        button_frame = tk.Frame(dialog)
        button_frame.pack(pady=10)
        
        def save_metadata():
            new_metadata = {key: entry.get() for key, entry in entries.items()}
            try:
                result = self.update_version_info(new_metadata)
                status_label.config(text=f"Metadata updated successfully! ({result})", fg="green")
                self.display_hex()
                self.modified = True
                title = "Hex Editor"
                if self.current_file:
                    title += f" - {os.path.basename(self.current_file)}"
                title += " *"
                self.root.title(title)
            except Exception as e:
                status_label.config(text=f"Error: {str(e)}", fg="red")
        
        def scramble_metadata():
            # Random company names
            companies = ["TechCorp Inc", "Digital Solutions LLC", "Quantum Systems", "CyberWorks Ltd", 
                        "Innovation Labs", "Global Tech Partners", "NextGen Software", "Elite Developers"]
            
            # Random product names
            products = ["SuperApp Pro", "DataManager", "SystemOptimizer", "SecureGuard", 
                       "PowerTools Suite", "CloudSync Manager", "NetMonitor Plus", "UltraUtility"]
            
            # Random descriptions
            descriptions = ["Advanced system utility", "Professional data management tool", 
                          "High-performance application", "Enterprise-grade solution",
                          "Comprehensive system software", "Innovative productivity tool"]
            
            # Generate random versions
            major = random.randint(1, 10)
            minor = random.randint(0, 99)
            build = random.randint(0, 9999)
            version = f"{major}.{minor}.{build}.0"
            
            # Random years for copyright
            year = random.randint(2015, 2025)
            
            # Generate random filename
            filename = ''.join(random.choices(string.ascii_lowercase, k=8)) + ".exe"
            
            # Update all fields
            entries['CompanyName'].delete(0, tk.END)
            entries['CompanyName'].insert(0, random.choice(companies))
            
            entries['ProductName'].delete(0, tk.END)
            entries['ProductName'].insert(0, random.choice(products))
            
            entries['FileDescription'].delete(0, tk.END)
            entries['FileDescription'].insert(0, random.choice(descriptions))
            
            entries['FileVersion'].delete(0, tk.END)
            entries['FileVersion'].insert(0, version)
            
            entries['ProductVersion'].delete(0, tk.END)
            entries['ProductVersion'].insert(0, version)
            
            entries['InternalName'].delete(0, tk.END)
            entries['InternalName'].insert(0, random.choice(products).replace(" ", ""))
            
            entries['OriginalFilename'].delete(0, tk.END)
            entries['OriginalFilename'].insert(0, filename)
            
            entries['LegalCopyright'].delete(0, tk.END)
            entries['LegalCopyright'].insert(0, f"Copyright © {year} {random.choice(companies)}")
            
            entries['LegalTrademarks'].delete(0, tk.END)
            if random.choice([True, False]):
                entries['LegalTrademarks'].insert(0, f"{random.choice(products)} is a trademark of {random.choice(companies)}")
            
            status_label.config(text="All fields randomized! Click Save Changes to apply.", fg="blue")
        
        tk.Button(button_frame, text="Save Changes", command=save_metadata, bg="#4CAF50", fg="white", padx=20).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Randomize All", command=scramble_metadata, bg="#FF9800", fg="white", padx=20).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Close", command=dialog.destroy, padx=20).pack(side=tk.LEFT, padx=5)
    
    def extract_version_info(self):
        """Extract version information from PE resource section"""
        metadata = {}
        
        try:
            # Find resource section
            pe_offset = struct.unpack('<I', self.data[60:64])[0]
            coff_offset = pe_offset + 4
            num_sections = struct.unpack('<H', self.data[coff_offset+2:coff_offset+4])[0]
            opt_header_size = struct.unpack('<H', self.data[coff_offset+16:coff_offset+18])[0]
            section_offset = coff_offset + 20 + opt_header_size
            
            # Look for .rsrc section
            rsrc_offset = None
            rsrc_size = None
            
            for i in range(num_sections):
                sect_start = section_offset + (i * 40)
                name = self.data[sect_start:sect_start+8].decode('ascii', errors='ignore').rstrip('\x00')
                
                if name == '.rsrc':
                    rsrc_offset = struct.unpack('<I', self.data[sect_start+20:sect_start+24])[0]
                    rsrc_size = struct.unpack('<I', self.data[sect_start+16:sect_start+20])[0]
                    break
            
            if rsrc_offset:
                # Search for common version strings in the resource section
                search_end = min(rsrc_offset + rsrc_size, len(self.data))
                
                # Common metadata strings to look for
                key_mapping = {
                    'CompanyName': b'C\x00o\x00m\x00p\x00a\x00n\x00y\x00N\x00a\x00m\x00e\x00\x00\x00',
                    'FileDescription': b'F\x00i\x00l\x00e\x00D\x00e\x00s\x00c\x00r\x00i\x00p\x00t\x00i\x00o\x00n\x00\x00\x00',
                    'FileVersion': b'F\x00i\x00l\x00e\x00V\x00e\x00r\x00s\x00i\x00o\x00n\x00\x00\x00',
                    'InternalName': b'I\x00n\x00t\x00e\x00r\x00n\x00a\x00l\x00N\x00a\x00m\x00e\x00\x00\x00',
                    'LegalCopyright': b'L\x00e\x00g\x00a\x00l\x00C\x00o\x00p\x00y\x00r\x00i\x00g\x00h\x00t\x00\x00\x00',
                    'LegalTrademarks': b'L\x00e\x00g\x00a\x00l\x00T\x00r\x00a\x00d\x00e\x00m\x00a\x00r\x00k\x00s\x00\x00\x00',
                    'OriginalFilename': b'O\x00r\x00i\x00g\x00i\x00n\x00a\x00l\x00F\x00i\x00l\x00e\x00n\x00a\x00m\x00e\x00\x00\x00',
                    'ProductName': b'P\x00r\x00o\x00d\x00u\x00c\x00t\x00N\x00a\x00m\x00e\x00\x00\x00',
                    'ProductVersion': b'P\x00r\x00o\x00d\x00u\x00c\x00t\x00V\x00e\x00r\x00s\x00i\x00o\x00n\x00\x00\x00',
                }
                
                for key_name, search_bytes in key_mapping.items():
                    # Find all occurrences
                    all_positions = []
                    search_pos = rsrc_offset
                    
                    while True:
                        pos = self.data.find(search_bytes, search_pos, search_end)
                        if pos == -1:
                            break
                        all_positions.append(pos)
                        search_pos = pos + 1
                    
                    # Try each position and use the one that gives a valid string
                    for pos in reversed(all_positions):  # Start from last occurrence
                        # The value immediately follows the key+null in the StringFileInfo structure
                        value_start = pos + len(search_bytes)
                        
                        # Align to 4-byte boundary
                        while value_start % 4 != 0:
                            value_start += 1
                        
                        # Read UTF-16LE string until we hit a null terminator
                        value_chars = []
                        idx = value_start
                        
                        while idx < search_end - 1:
                            byte1 = self.data[idx]
                            byte2 = self.data[idx + 1]
                            
                            # Check for null terminator
                            if byte1 == 0 and byte2 == 0:
                                break
                            
                            # Check for non-printable or invalid characters (likely hit next field)
                            char_code = byte1 | (byte2 << 8)
                            if char_code > 0 and char_code < 0xFFFF:
                                try:
                                    char = chr(char_code)
                                    # Stop if we hit another key pattern or non-printable
                                    if char_code < 32 and char_code not in [9, 10, 13]:  # Allow tabs, newlines
                                        break
                                    value_chars.append(char)
                                except:
                                    break
                            else:
                                break
                            
                            idx += 2
                            if len(value_chars) > 500:  # Safety limit
                                break
                        
                        if value_chars:
                            value = ''.join(value_chars).strip()
                            # Validate it looks like a reasonable value (not just garbage)
                            if value and len(value) > 0:
                                # For FileVersion and ProductVersion, expect something like "1.2.3.4"
                                if key_name in ['FileVersion', 'ProductVersion']:
                                    # Check if it contains at least one digit or period
                                    if any(c.isdigit() or c == '.' for c in value):
                                        metadata[key_name] = value
                                        break
                                else:
                                    metadata[key_name] = value
                                    break
        
        except Exception as e:
            pass
        
        return metadata
    
    def update_version_info(self, new_metadata):
        """Update version information in PE resource section"""
        updated_fields = []
        truncated_fields = []
        warnings = []
        
        try:
            # Find resource section
            pe_offset = struct.unpack('<I', self.data[60:64])[0]
            coff_offset = pe_offset + 4
            num_sections = struct.unpack('<H', self.data[coff_offset+2:coff_offset+4])[0]
            opt_header_size = struct.unpack('<H', self.data[coff_offset+16:coff_offset+18])[0]
            section_offset = coff_offset + 20 + opt_header_size
            
            # Look for .rsrc section
            rsrc_offset = None
            rsrc_size = None
            
            for i in range(num_sections):
                sect_start = section_offset + (i * 40)
                name = self.data[sect_start:sect_start+8].decode('ascii', errors='ignore').rstrip('\x00')
                
                if name == '.rsrc':
                    rsrc_offset = struct.unpack('<I', self.data[sect_start+20:sect_start+24])[0]
                    rsrc_size = struct.unpack('<I', self.data[sect_start+16:sect_start+20])[0]
                    break
            
            if not rsrc_offset:
                raise Exception("No resource section found")
            
            search_end = min(rsrc_offset + rsrc_size, len(self.data))
            
            # Use same mapping as extraction
            key_mapping = {
                'CompanyName': b'C\x00o\x00m\x00p\x00a\x00n\x00y\x00N\x00a\x00m\x00e\x00\x00\x00',
                'FileDescription': b'F\x00i\x00l\x00e\x00D\x00e\x00s\x00c\x00r\x00i\x00p\x00t\x00i\x00o\x00n\x00\x00\x00',
                'FileVersion': b'F\x00i\x00l\x00e\x00V\x00e\x00r\x00s\x00i\x00o\x00n\x00\x00\x00',
                'InternalName': b'I\x00n\x00t\x00e\x00r\x00n\x00a\x00l\x00N\x00a\x00m\x00e\x00\x00\x00',
                'LegalCopyright': b'L\x00e\x00g\x00a\x00l\x00C\x00o\x00p\x00y\x00r\x00i\x00g\x00h\x00t\x00\x00\x00',
                'LegalTrademarks': b'L\x00e\x00g\x00a\x00l\x00T\x00r\x00a\x00d\x00e\x00m\x00a\x00r\x00k\x00s\x00\x00\x00',
                'OriginalFilename': b'O\x00r\x00i\x00g\x00i\x00n\x00a\x00l\x00F\x00i\x00l\x00e\x00n\x00a\x00m\x00e\x00\x00\x00',
                'ProductName': b'P\x00r\x00o\x00d\x00u\x00c\x00t\x00N\x00a\x00m\x00e\x00\x00\x00',
                'ProductVersion': b'P\x00r\x00o\x00d\x00u\x00c\x00t\x00V\x00e\x00r\x00s\x00i\x00o\x00n\x00\x00\x00',
            }
            
            for key_name, new_value in new_metadata.items():
                if key_name not in key_mapping:
                    continue
                
                search_bytes = key_mapping[key_name]
                
                # Find all occurrences and use the last one (same as extraction)
                pos = -1
                last_valid_pos = -1
                search_pos = rsrc_offset
                
                while True:
                    pos = self.data.find(search_bytes, search_pos, search_end)
                    if pos == -1:
                        break
                    last_valid_pos = pos
                    search_pos = pos + 1
                
                if last_valid_pos != -1:
                    pos = last_valid_pos
                    # Value starts after key
                    value_start = pos + len(search_bytes)
                    
                    # Align to 4-byte boundary (same as extraction)
                    while value_start % 4 != 0:
                        value_start += 1
                    
                    # Find current value end (read same way as extraction)
                    value_end = value_start
                    while value_end < search_end - 1:
                        byte1 = self.data[value_end]
                        byte2 = self.data[value_end + 1]
                        
                        if byte1 == 0 and byte2 == 0:
                            break
                        
                        value_end += 2
                        if value_end - value_start > 1000:
                            break
                    
                    current_length = value_end - value_start
                    max_chars = current_length // 2  # UTF-16LE: 2 bytes per char
                    
                    # Encode new value
                    new_value_bytes = new_value.encode('utf-16-le') if new_value else b''
                    
                    # Check if truncation needed
                    if len(new_value_bytes) > current_length:
                        truncated_value = new_value[:max_chars]
                        new_value_bytes = truncated_value.encode('utf-16-le')
                        truncated_fields.append(f"{key_name} (max {max_chars} chars)")
                    
                    # Clear the entire old value area first
                    for i in range(current_length):
                        self.data[value_start + i] = 0
                    
                    # Write new value
                    for i in range(len(new_value_bytes)):
                        self.data[value_start + i] = new_value_bytes[i]
                    
                    updated_fields.append(key_name)
                else:
                    warnings.append(f"{key_name} not found")
        
        except Exception as e:
            raise Exception(f"Failed to update metadata: {str(e)}")
        
        result = f"{len(updated_fields)} updated"
        if truncated_fields:
            result += f", {len(truncated_fields)} truncated"
        if warnings:
            result += f", {len(warnings)} not found"
        
        return result
    
    def scan_malware(self):
        """Scan file for common malware indicators"""
        if not self.data:
            messagebox.showinfo("No File", "Please open a file first")
            return
        
        # Clear previous malware highlights
        self.text_widget.tag_remove("malware", 1.0, tk.END)
        
        detections = []
        
        # Suspicious strings (common in malware)
        suspicious_strings = [
            (b"cmd.exe", "Command Prompt execution"),
            (b"powershell", "PowerShell execution"),
            (b"rundll32", "DLL execution"),
            (b"regsvr32", "Register DLL"),
            (b"schtasks", "Task scheduler"),
            (b"netsh", "Network configuration"),
            (b"whoami", "User enumeration"),
            (b"taskkill", "Process termination"),
            (b"reg add", "Registry modification"),
            (b"reg delete", "Registry deletion"),
            (b"HKEY_CURRENT_USER", "Registry access"),
            (b"HKEY_LOCAL_MACHINE", "System registry access"),
            (b"SeDebugPrivilege", "Debug privilege escalation"),
            (b"CreateRemoteThread", "Code injection"),
            (b"VirtualAllocEx", "Memory allocation (injection)"),
            (b"WriteProcessMemory", "Process memory write"),
            (b"LoadLibrary", "DLL loading"),
            (b"GetProcAddress", "Function address retrieval"),
            (b"ShellExecute", "Execute command"),
            (b"WinExec", "Execute program"),
            (b"CreateProcess", "Process creation"),
            (b"URLDownloadToFile", "Download file"),
            (b"InternetOpen", "Internet connection"),
            (b"HttpSendRequest", "HTTP request"),
            (b"socket", "Network socket"),
            (b"connect", "Network connection"),
            (b"send", "Send data"),
            (b"recv", "Receive data"),
            (b"keybd_event", "Keyboard simulation"),
            (b"mouse_event", "Mouse simulation"),
            (b"GetAsyncKeyState", "Keylogger indicator"),
            (b"SetWindowsHook", "Keyboard/mouse hook"),
            (b"CryptEncrypt", "Encryption (ransomware)"),
            (b"CryptDecrypt", "Decryption"),
            (b"bitcoin", "Cryptocurrency"),
            (b"wallet.dat", "Cryptocurrency wallet"),
            (b"ransom", "Ransomware indicator"),
            (b".onion", "Tor network"),
            (b"mimikatz", "Credential dumping tool"),
            (b"password", "Password access"),
            (b"admin", "Admin access"),
            (b"privilege", "Privilege escalation"),
        ]
        
        # Search for suspicious strings
        for pattern, description in suspicious_strings:
            pos = 0
            while True:
                pos = self.data.find(pattern, pos)
                if pos == -1:
                    break
                
                # Check for nearby IP addresses or URLs
                extra_info = ""
                if any(net_term in pattern.lower() for net_term in [b"internet", b"http", b"socket", b"connect", b"send", b"recv"]):
                    nearby_data = self.extract_nearby_network_info(pos)
                    if nearby_data:
                        extra_info = f" -> {nearby_data}"
                
                detections.append({
                    'offset': pos,
                    'length': len(pattern),
                    'description': description + extra_info,
                    'pattern': pattern.decode('ascii', errors='replace')
                })
                
                # Highlight in hex view
                self.highlight_malware_offset(pos, len(pattern))
                pos += 1
        
        # Search for IP addresses
        ip_addresses = self.find_ip_addresses()
        for ip_offset, ip_str in ip_addresses:
            detections.append({
                'offset': ip_offset,
                'length': len(ip_str),
                'description': f"IP Address: {ip_str}",
                'pattern': ip_str
            })
            self.highlight_malware_offset(ip_offset, len(ip_str))
        
        # Search for URLs
        urls = self.find_urls()
        for url_offset, url_str in urls:
            detections.append({
                'offset': url_offset,
                'length': len(url_str),
                'description': f"URL: {url_str}",
                'pattern': url_str
            })
            self.highlight_malware_offset(url_offset, len(url_str))
        
        # Suspicious byte patterns
        suspicious_patterns = [
            (b"\x4D\x5A\x90\x00", "Embedded PE file"),  # MZ header
            (b"\x50\x4B\x03\x04", "Embedded ZIP/JAR"),
            (b"\xFF\xD5", "Call instruction (shellcode)"),
            (b"\x55\x8B\xEC", "Common function prologue"),
        ]
        
        for pattern, description in suspicious_patterns:
            pos = 0
            while True:
                pos = self.data.find(pattern, pos)
                if pos == -1:
                    break
                
                detections.append({
                    'offset': pos,
                    'length': len(pattern),
                    'description': description,
                    'pattern': pattern.hex()
                })
                
                self.highlight_malware_offset(pos, len(pattern))
                pos += 1
        
        # Show results
        self.show_malware_results(detections)
    
    def check_program_errors(self):
        """Check PE/ELF file structure for errors and corruption"""
        if not self.data:
            messagebox.showinfo("No File", "Please open a file first")
            return
        
        errors = []
        warnings = []
        info = []
        
        # Check if PE file (Windows executable)
        if self.is_pe_file():
            self.check_pe_errors(errors, warnings, info)
        # Check if ELF file (Linux executable)
        elif self.is_elf_file():
            self.check_elf_errors(errors, warnings, info)
        else:
            messagebox.showinfo("Not Executable", "This file is not a recognized executable format (PE or ELF)")
            return
        
        # Show results in a dialog
        self.show_error_check_results(errors, warnings, info)
    
    def check_pe_errors(self, errors, warnings, info):
        """Check PE file structure for errors"""
        data = self.data
        
        # Check DOS Header
        if len(data) < 64:
            errors.append(("DOS Header", "File too small for valid DOS header (need at least 64 bytes)", 0))
            return
        
        # Check MZ signature
        if data[0:2] != b'MZ':
            errors.append(("DOS Header", f"Invalid MZ signature: expected 'MZ', got '{data[0:2].hex()}'", 0))
            return
        else:
            info.append(("DOS Header", "Valid MZ signature found", 0))
        
        # Get PE header offset from DOS header
        pe_offset = struct.unpack('<I', data[0x3C:0x40])[0]
        
        if pe_offset < 0 or pe_offset > len(data) - 4:
            errors.append(("DOS Header", f"Invalid PE header offset: {pe_offset} (file size: {len(data)})", 0x3C))
            return
        else:
            info.append(("PE Offset", f"PE header at offset 0x{pe_offset:X}", 0x3C))
        
        # Check PE signature
        if len(data) < pe_offset + 4:
            errors.append(("PE Header", "File truncated before PE signature", pe_offset))
            return
        
        pe_sig = data[pe_offset:pe_offset+4]
        if pe_sig != b'PE\x00\x00':
            errors.append(("PE Signature", f"Invalid PE signature at 0x{pe_offset:X}: expected 'PE\\x00\\x00', got '{pe_sig.hex()}'", pe_offset))
            return
        else:
            info.append(("PE Signature", "Valid PE signature found", pe_offset))
        
        # Parse COFF File Header
        coff_offset = pe_offset + 4
        if len(data) < coff_offset + 20:
            errors.append(("COFF Header", "File truncated at COFF header", coff_offset))
            return
        
        machine = struct.unpack('<H', data[coff_offset:coff_offset+2])[0]
        num_sections = struct.unpack('<H', data[coff_offset+2:coff_offset+4])[0]
        timestamp = struct.unpack('<I', data[coff_offset+4:coff_offset+8])[0]
        symbol_table_ptr = struct.unpack('<I', data[coff_offset+8:coff_offset+12])[0]
        num_symbols = struct.unpack('<I', data[coff_offset+12:coff_offset+16])[0]
        opt_header_size = struct.unpack('<H', data[coff_offset+16:coff_offset+18])[0]
        characteristics = struct.unpack('<H', data[coff_offset+18:coff_offset+20])[0]
        
        # Validate machine type
        machine_types = {
            0x0: "Unknown", 0x14c: "i386", 0x166: "MIPS R4000", 0x1a2: "Hitachi SH3",
            0x1a6: "Hitachi SH4", 0x1c0: "ARM", 0x1c4: "ARM Thumb",
            0x8664: "AMD64 (x64)", 0xAA64: "ARM64"
        }
        if machine in machine_types:
            info.append(("Machine", f"Machine type: {machine_types[machine]} (0x{machine:X})", coff_offset))
        else:
            warnings.append(("Machine", f"Unknown machine type: 0x{machine:X}", coff_offset))
        
        # Check number of sections
        if num_sections == 0:
            errors.append(("Sections", "No sections defined (suspicious)", coff_offset+2))
        elif num_sections > 96:
            warnings.append(("Sections", f"Unusually high number of sections: {num_sections} (max typically 96)", coff_offset+2))
        else:
            info.append(("Sections", f"Number of sections: {num_sections}", coff_offset+2))
        
        # Parse Optional Header
        opt_header_offset = coff_offset + 20
        if len(data) < opt_header_offset + opt_header_size:
            errors.append(("Optional Header", f"File truncated at optional header (expected {opt_header_size} bytes)", opt_header_offset))
            return
        
        if opt_header_size == 0:
            warnings.append(("Optional Header", "No optional header present", opt_header_offset))
        else:
            # Check PE type (PE32 or PE32+)
            magic = struct.unpack('<H', data[opt_header_offset:opt_header_offset+2])[0]
            if magic == 0x10b:
                pe_type = "PE32 (32-bit)"
                addr_size = 4
                info.append(("PE Type", pe_type, opt_header_offset))
            elif magic == 0x20b:
                pe_type = "PE32+ (64-bit)"
                addr_size = 8
                info.append(("PE Type", pe_type, opt_header_offset))
            else:
                errors.append(("PE Type", f"Invalid optional header magic: 0x{magic:X} (expected 0x10B or 0x20B)", opt_header_offset))
                return
            
            # Check entry point
            entry_point_offset = opt_header_offset + 16
            entry_point = struct.unpack('<I', data[entry_point_offset:entry_point_offset+4])[0]
            
            if entry_point == 0:
                warnings.append(("Entry Point", "Entry point is 0 (may be DLL or corrupted)", entry_point_offset))
            else:
                info.append(("Entry Point", f"Entry point RVA: 0x{entry_point:X}", entry_point_offset))
            
            # Check image base
            if magic == 0x10b:  # PE32
                image_base_offset = opt_header_offset + 28
                image_base = struct.unpack('<I', data[image_base_offset:image_base_offset+4])[0]
            else:  # PE32+
                image_base_offset = opt_header_offset + 24
                image_base = struct.unpack('<Q', data[image_base_offset:image_base_offset+8])[0]
            
            info.append(("Image Base", f"Image base: 0x{image_base:X}", image_base_offset))
            
            # Check section alignment
            if magic == 0x10b:
                sect_align_offset = opt_header_offset + 32
            else:
                sect_align_offset = opt_header_offset + 32
            
            section_alignment = struct.unpack('<I', data[sect_align_offset:sect_align_offset+4])[0]
            file_alignment = struct.unpack('<I', data[sect_align_offset+4:sect_align_offset+8])[0]
            
            if section_alignment < file_alignment:
                errors.append(("Alignment", f"Section alignment (0x{section_alignment:X}) < File alignment (0x{file_alignment:X})", sect_align_offset))
            else:
                info.append(("Alignment", f"Section alignment: 0x{section_alignment:X}, File alignment: 0x{file_alignment:X}", sect_align_offset))
            
            # Check if file alignment is power of 2 between 512 and 64K
            if file_alignment != 0 and (file_alignment & (file_alignment - 1)) != 0:
                warnings.append(("File Alignment", f"File alignment (0x{file_alignment:X}) is not a power of 2", sect_align_offset+4))
            elif file_alignment < 512 or file_alignment > 65536:
                warnings.append(("File Alignment", f"File alignment (0x{file_alignment:X}) outside typical range (512-64K)", sect_align_offset+4))
            
            # Get size of image
            if magic == 0x10b:
                size_of_image_offset = opt_header_offset + 56
            else:
                size_of_image_offset = opt_header_offset + 56
            
            size_of_image = struct.unpack('<I', data[size_of_image_offset:size_of_image_offset+4])[0]
            size_of_headers = struct.unpack('<I', data[size_of_image_offset+4:size_of_image_offset+8])[0]
            
            info.append(("Size of Image", f"Size of image in memory: 0x{size_of_image:X} ({size_of_image} bytes)", size_of_image_offset))
            info.append(("Size of Headers", f"Size of headers: 0x{size_of_headers:X} ({size_of_headers} bytes)", size_of_image_offset+4))
            
            if size_of_headers > len(data):
                errors.append(("Headers Size", f"Size of headers ({size_of_headers}) exceeds file size ({len(data)})", size_of_image_offset+4))
            
            # Check checksum
            checksum_offset = size_of_image_offset + 8
            stored_checksum = struct.unpack('<I', data[checksum_offset:checksum_offset+4])[0]
            if stored_checksum == 0:
                warnings.append(("Checksum", "PE checksum is 0 (not critical but unusual for signed files)", checksum_offset))
            else:
                # Calculate checksum
                calculated_checksum = self.calculate_pe_checksum(checksum_offset)
                if calculated_checksum != stored_checksum:
                    warnings.append(("Checksum", f"PE checksum mismatch: stored=0x{stored_checksum:X}, calculated=0x{calculated_checksum:X}", checksum_offset))
                else:
                    info.append(("Checksum", f"PE checksum valid: 0x{stored_checksum:X}", checksum_offset))
        
        # Parse Section Headers
        section_table_offset = opt_header_offset + opt_header_size
        section_size = 40  # Each section header is 40 bytes
        
        for i in range(num_sections):
            sect_offset = section_table_offset + (i * section_size)
            
            if len(data) < sect_offset + section_size:
                errors.append(("Section Table", f"File truncated at section {i+1} header", sect_offset))
                break
            
            # Get section name
            name_bytes = data[sect_offset:sect_offset+8]
            try:
                name = name_bytes.rstrip(b'\x00').decode('ascii', errors='replace')
            except:
                name = name_bytes.hex()
            
            virtual_size = struct.unpack('<I', data[sect_offset+8:sect_offset+12])[0]
            virtual_addr = struct.unpack('<I', data[sect_offset+12:sect_offset+16])[0]
            raw_size = struct.unpack('<I', data[sect_offset+16:sect_offset+20])[0]
            raw_ptr = struct.unpack('<I', data[sect_offset+20:sect_offset+24])[0]
            characteristics = struct.unpack('<I', data[sect_offset+36:sect_offset+40])[0]
            
            # Check for section errors
            if raw_ptr > 0 and raw_ptr + raw_size > len(data):
                errors.append((f"Section '{name}'", f"Section data extends beyond file: offset=0x{raw_ptr:X}, size=0x{raw_size:X}, file_size=0x{len(data):X}", sect_offset))
            elif raw_ptr > 0 and raw_size > 0:
                info.append((f"Section '{name}'", f"Valid section at offset 0x{raw_ptr:X}, size 0x{raw_size:X}", sect_offset))
            
            # Check for suspicious section characteristics
            is_executable = characteristics & 0x20000000  # IMAGE_SCN_MEM_EXECUTE
            is_writable = characteristics & 0x80000000  # IMAGE_SCN_MEM_WRITE
            
            if is_executable and is_writable:
                warnings.append((f"Section '{name}'", "Section is both writable and executable (potential code injection)", sect_offset+36))
            
            # Check for suspicious section names
            suspicious_names = ['.upx', 'UPX0', 'UPX1', '.aspack', '.nsp', '.vmp', '.themida']
            if any(name.lower().startswith(s) or s in name.lower() for s in suspicious_names):
                warnings.append((f"Section '{name}'", f"Suspicious packer-related section name detected", sect_offset))
    
    def check_elf_errors(self, errors, warnings, info):
        """Check ELF file structure for errors"""
        data = self.data
        
        # Check ELF magic
        if len(data) < 52:
            errors.append(("ELF Header", "File too small for valid ELF header", 0))
            return
        
        if data[0:4] != b'\x7fELF':
            errors.append(("ELF Magic", f"Invalid ELF magic: {data[0:4].hex()}", 0))
            return
        else:
            info.append(("ELF Magic", "Valid ELF signature found", 0))
        
        # Check ELF class (32/64 bit)
        elf_class = data[4]
        if elf_class == 1:
            info.append(("ELF Class", "32-bit ELF (ELFCLASS32)", 4))
            is_64bit = False
            header_size = 52
            phent_size_expected = 32
            shent_size_expected = 40
        elif elf_class == 2:
            info.append(("ELF Class", "64-bit ELF (ELFCLASS64)", 4))
            is_64bit = True
            header_size = 64
            phent_size_expected = 56
            shent_size_expected = 64
        else:
            errors.append(("ELF Class", f"Invalid ELF class: {elf_class}", 4))
            return
        
        # Check data encoding (endianness)
        encoding = data[5]
        if encoding == 1:
            info.append(("Encoding", "Little-endian (LSB)", 5))
            endian = '<'
        elif encoding == 2:
            info.append(("Encoding", "Big-endian (MSB)", 5))
            endian = '>'
        else:
            errors.append(("Encoding", f"Invalid data encoding: {encoding}", 5))
            return
        
        # Check ELF version
        version = data[6]
        if version != 1:
            warnings.append(("ELF Version", f"Unexpected ELF version: {version}", 6))
        else:
            info.append(("ELF Version", "Version 1 (current)", 6))
        
        # Check OS/ABI
        osabi = data[7]
        osabi_names = {
            0: "UNIX System V", 1: "HP-UX", 2: "NetBSD", 3: "Linux",
            6: "Solaris", 7: "AIX", 8: "IRIX", 9: "FreeBSD", 10: "Tru64",
            11: "Novell Modesto", 12: "OpenBSD", 13: "OpenVMS", 14: "HP NonStop",
            15: "AROS", 16: "FenixOS", 17: "CloudABI", 97: "ARM", 255: "Standalone"
        }
        osabi_name = osabi_names.get(osabi, f"Unknown (0x{osabi:X})")
        info.append(("OS/ABI", osabi_name, 7))
        
        if len(data) < header_size:
            errors.append(("ELF Header", f"File too small for complete ELF header ({len(data)} < {header_size})", 0))
            return
        
        # Parse ELF type
        e_type = struct.unpack(endian + 'H', data[16:18])[0]
        type_names = {0: "None", 1: "Relocatable", 2: "Executable", 3: "Shared Object", 4: "Core"}
        type_name = type_names.get(e_type, f"Unknown (0x{e_type:X})")
        info.append(("ELF Type", type_name, 16))
        
        # Parse machine type
        e_machine = struct.unpack(endian + 'H', data[18:20])[0]
        machine_names = {
            0: "None", 3: "x86", 8: "MIPS", 20: "PowerPC", 40: "ARM",
            62: "x86-64", 183: "ARM64", 243: "RISC-V"
        }
        machine_name = machine_names.get(e_machine, f"Unknown (0x{e_machine:X})")
        info.append(("Machine", machine_name, 18))
        
        # Parse entry point and header offsets based on class
        if is_64bit:
            e_entry = struct.unpack(endian + 'Q', data[24:32])[0]
            e_phoff = struct.unpack(endian + 'Q', data[32:40])[0]
            e_shoff = struct.unpack(endian + 'Q', data[40:48])[0]
            e_phentsize = struct.unpack(endian + 'H', data[54:56])[0]
            e_phnum = struct.unpack(endian + 'H', data[56:58])[0]
            e_shentsize = struct.unpack(endian + 'H', data[58:60])[0]
            e_shnum = struct.unpack(endian + 'H', data[60:62])[0]
        else:
            e_entry = struct.unpack(endian + 'I', data[24:28])[0]
            e_phoff = struct.unpack(endian + 'I', data[28:32])[0]
            e_shoff = struct.unpack(endian + 'I', data[32:36])[0]
            e_phentsize = struct.unpack(endian + 'H', data[42:44])[0]
            e_phnum = struct.unpack(endian + 'H', data[44:46])[0]
            e_shentsize = struct.unpack(endian + 'H', data[46:48])[0]
            e_shnum = struct.unpack(endian + 'H', data[48:50])[0]
        
        if e_entry != 0:
            info.append(("Entry Point", f"Entry point: 0x{e_entry:X}", 24 if is_64bit else 24))
        else:
            warnings.append(("Entry Point", "Entry point is 0 (may be shared library)", 24))
        
        # Check program headers
        if e_phoff > 0:
            if e_phoff > len(data):
                errors.append(("Program Headers", f"Program header offset (0x{e_phoff:X}) beyond file size", 32 if is_64bit else 28))
            else:
                info.append(("Program Headers", f"{e_phnum} program headers at offset 0x{e_phoff:X}", 32 if is_64bit else 28))
                
                if e_phentsize != phent_size_expected:
                    warnings.append(("Program Header Size", f"Unexpected program header entry size: {e_phentsize} (expected {phent_size_expected})", 54 if is_64bit else 42))
                
                # Validate program headers don't exceed file
                if e_phoff + (e_phnum * e_phentsize) > len(data):
                    errors.append(("Program Headers", f"Program headers extend beyond file", e_phoff))
        
        # Check section headers
        if e_shoff > 0:
            if e_shoff > len(data):
                errors.append(("Section Headers", f"Section header offset (0x{e_shoff:X}) beyond file size", 40 if is_64bit else 32))
            else:
                info.append(("Section Headers", f"{e_shnum} section headers at offset 0x{e_shoff:X}", 40 if is_64bit else 32))
                
                if e_shentsize != shent_size_expected:
                    warnings.append(("Section Header Size", f"Unexpected section header entry size: {e_shentsize} (expected {shent_size_expected})", 58 if is_64bit else 46))
                
                # Validate section headers don't exceed file
                if e_shoff + (e_shnum * e_shentsize) > len(data):
                    errors.append(("Section Headers", f"Section headers extend beyond file", e_shoff))
    
    def calculate_pe_checksum(self, checksum_offset):
        """Calculate PE checksum"""
        data = self.data
        checksum = 0
        
        # Process file as 16-bit words, skipping checksum field
        for i in range(0, len(data), 2):
            if i == checksum_offset or i == checksum_offset + 2:
                continue
            
            if i + 2 <= len(data):
                word = struct.unpack('<H', data[i:i+2])[0]
            else:
                word = data[i]
            
            checksum = (checksum + word) & 0xFFFFFFFF
        
        # Fold to 16 bits and add file size
        checksum = ((checksum & 0xFFFF) + (checksum >> 16)) & 0xFFFFFFFF
        checksum = ((checksum & 0xFFFF) + (checksum >> 16)) & 0xFFFFFFFF
        checksum = (checksum + len(data)) & 0xFFFFFFFF
        
        return checksum
    
    def show_error_check_results(self, errors, warnings, info):
        """Display error check results in a dialog"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Program Error Check Results")
        dialog.geometry("800x600")
        dialog.transient(self.root)
        
        # Summary frame
        summary_frame = tk.Frame(dialog, bg="#f0f0f0", pady=10)
        summary_frame.pack(fill=tk.X, padx=10, pady=5)
        
        # Calculate status
        if errors:
            status_text = f"❌ {len(errors)} Error(s) Found"
            status_color = "#D32F2F"
        elif warnings:
            status_text = f"⚠️ {len(warnings)} Warning(s)"
            status_color = "#FF9800"
        else:
            status_text = "✓ No Errors Found"
            status_color = "#4CAF50"
        
        status_label = tk.Label(summary_frame, text=status_text, font=("Arial", 14, "bold"), 
                               bg="#f0f0f0", fg=status_color)
        status_label.pack()
        
        summary_text = f"Errors: {len(errors)} | Warnings: {len(warnings)} | Info: {len(info)}"
        tk.Label(summary_frame, text=summary_text, font=("Arial", 10), bg="#f0f0f0").pack()
        
        # Notebook for tabs
        notebook = ttk.Notebook(dialog)
        notebook.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        # Create tabs for each category
        def create_results_tab(parent, items, color, is_fixable=False):
            frame = tk.Frame(parent)
            
            # Treeview for results
            columns = ("Category", "Description", "Offset")
            tree = ttk.Treeview(frame, columns=columns, show="headings", height=20)
            
            tree.heading("Category", text="Category")
            tree.heading("Description", text="Description")
            tree.heading("Offset", text="Offset")
            
            tree.column("Category", width=120)
            tree.column("Description", width=500)
            tree.column("Offset", width=100)
            
            # Scrollbar
            scrollbar = ttk.Scrollbar(frame, orient=tk.VERTICAL, command=tree.yview)
            tree.configure(yscrollcommand=scrollbar.set)
            
            # Add items
            for category, desc, offset in items:
                tree.insert("", tk.END, values=(category, desc, f"0x{offset:X}"))
            
            tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            
            # Double-click to navigate
            def on_double_click(event):
                selection = tree.selection()
                if selection:
                    item = tree.item(selection[0])
                    offset_str = item['values'][2]
                    try:
                        offset = int(offset_str, 16)
                        self.highlight_offset(offset, 1)
                    except:
                        pass
            
            tree.bind("<Double-1>", on_double_click)
            
            # Right-click context menu for errors/warnings
            if is_fixable:
                context_menu = tk.Menu(tree, tearoff=0)
                context_menu.add_command(label="Go to Offset", command=lambda: go_to_selected(tree))
                context_menu.add_separator()
                context_menu.add_command(label="🔧 Fix Error", command=lambda: fix_selected_error(tree, dialog))
                context_menu.add_command(label="ℹ️ More Info", command=lambda: show_error_info(tree))
                
                def show_context_menu(event):
                    # Select the item under cursor
                    item = tree.identify_row(event.y)
                    if item:
                        tree.selection_set(item)
                        context_menu.post(event.x_root, event.y_root)
                
                def go_to_selected(tree):
                    selection = tree.selection()
                    if selection:
                        item = tree.item(selection[0])
                        offset_str = item['values'][2]
                        try:
                            offset = int(offset_str, 16)
                            self.highlight_offset(offset, 1)
                        except:
                            pass
                
                def fix_selected_error(tree, dialog):
                    selection = tree.selection()
                    if selection:
                        item = tree.item(selection[0])
                        category = item['values'][0]
                        description = item['values'][1]
                        offset_str = item['values'][2]
                        try:
                            offset = int(offset_str, 16)
                            self.attempt_fix_error(category, description, offset, tree, selection[0], dialog)
                        except Exception as e:
                            messagebox.showerror("Fix Error", f"Failed to fix error: {str(e)}")
                
                def show_error_info(tree):
                    selection = tree.selection()
                    if selection:
                        item = tree.item(selection[0])
                        category = item['values'][0]
                        description = item['values'][1]
                        offset_str = item['values'][2]
                        info_text = self.get_error_explanation(category, description)
                        messagebox.showinfo(f"Error Info: {category}", info_text)
                
                tree.bind("<Button-3>", show_context_menu)
            
            return frame
        
        # Errors tab
        if errors:
            errors_tab = create_results_tab(notebook, errors, "#D32F2F", is_fixable=True)
            notebook.add(errors_tab, text=f"❌ Errors ({len(errors)})")
        
        # Warnings tab
        if warnings:
            warnings_tab = create_results_tab(notebook, warnings, "#FF9800", is_fixable=True)
            notebook.add(warnings_tab, text=f"⚠️ Warnings ({len(warnings)})")
        
        # Info tab
        info_tab = create_results_tab(notebook, info, "#2196F3")
        notebook.add(info_tab, text=f"ℹ️ Info ({len(info)})")
        
        # Close button
        tk.Button(dialog, text="Close", command=dialog.destroy, width=15).pack(pady=10)
    
    def attempt_fix_error(self, category, description, offset, tree, item_id, dialog):
        """Attempt to fix a detected error in the PE/ELF file"""
        fix_applied = False
        fix_description = ""
        
        # PE-specific fixes
        if "MZ signature" in description or category == "DOS Header" and "MZ" in description:
            # Fix invalid MZ signature
            if messagebox.askyesno("Fix MZ Signature", 
                "This will write 'MZ' (0x4D5A) at offset 0x0.\n\nThis is the DOS header signature required for PE files.\n\nApply fix?"):
                self.data[0:2] = b'MZ'
                fix_applied = True
                fix_description = "Fixed MZ signature at offset 0x0"
        
        elif "PE signature" in description.lower() or category == "PE Signature":
            # Fix invalid PE signature
            if messagebox.askyesno("Fix PE Signature", 
                f"This will write 'PE\\x00\\x00' at offset 0x{offset:X}.\n\nThis is the PE header signature required for Windows executables.\n\nApply fix?"):
                self.data[offset:offset+4] = b'PE\x00\x00'
                fix_applied = True
                fix_description = f"Fixed PE signature at offset 0x{offset:X}"
        
        elif "PE checksum" in description.lower() or category == "Checksum":
            # Fix checksum
            if "mismatch" in description.lower() or "checksum is 0" in description.lower():
                if messagebox.askyesno("Fix PE Checksum", 
                    f"This will recalculate and write the correct PE checksum at offset 0x{offset:X}.\n\nApply fix?"):
                    new_checksum = self.calculate_pe_checksum(offset)
                    checksum_bytes = struct.pack('<I', new_checksum)
                    self.data[offset:offset+4] = checksum_bytes
                    fix_applied = True
                    fix_description = f"Fixed PE checksum to 0x{new_checksum:X} at offset 0x{offset:X}"
        
        elif "writable and executable" in description.lower():
            # Fix section with both write and execute flags
            if messagebox.askyesno("Fix Section Characteristics", 
                f"This section has both WRITE and EXECUTE permissions, which is a security risk.\n\n"
                f"Options:\n"
                f"1. Remove WRITE flag (make read-only executable)\n"
                f"2. Remove EXECUTE flag (make writable data)\n\n"
                f"Click YES to remove WRITE flag, NO to cancel.\n"
                f"(You can manually edit at offset 0x{offset:X} for other options)"):
                # Read current characteristics
                current = struct.unpack('<I', self.data[offset:offset+4])[0]
                # Remove IMAGE_SCN_MEM_WRITE (0x80000000)
                new_chars = current & ~0x80000000
                self.data[offset:offset+4] = struct.pack('<I', new_chars)
                fix_applied = True
                fix_description = f"Removed WRITE flag from section characteristics at offset 0x{offset:X}"
        
        elif "alignment" in description.lower() and "Section alignment" in description:
            # Fix section alignment issue
            if messagebox.askyesno("Fix Alignment", 
                f"Section alignment is less than file alignment, which is invalid.\n\n"
                f"This will set section alignment equal to file alignment.\n\n"
                f"Apply fix at offset 0x{offset:X}?"):
                # Read file alignment (4 bytes after section alignment)
                file_alignment = struct.unpack('<I', self.data[offset+4:offset+8])[0]
                self.data[offset:offset+4] = struct.pack('<I', file_alignment)
                fix_applied = True
                fix_description = f"Fixed section alignment to 0x{file_alignment:X} at offset 0x{offset:X}"
        
        elif "File alignment" in description and "power of 2" in description.lower():
            # Fix file alignment not power of 2
            current = struct.unpack('<I', self.data[offset:offset+4])[0]
            # Round up to nearest power of 2
            if current > 0:
                new_align = 1
                while new_align < current:
                    new_align *= 2
                if new_align > 65536:
                    new_align = 65536
            else:
                new_align = 512
            
            if messagebox.askyesno("Fix File Alignment", 
                f"File alignment (0x{current:X}) is not a power of 2.\n\n"
                f"This will set it to 0x{new_align:X}.\n\n"
                f"Apply fix at offset 0x{offset:X}?"):
                self.data[offset:offset+4] = struct.pack('<I', new_align)
                fix_applied = True
                fix_description = f"Fixed file alignment to 0x{new_align:X} at offset 0x{offset:X}"
        
        elif "Entry point is 0" in description:
            # Can't auto-fix entry point - need user input
            messagebox.showinfo("Cannot Auto-Fix", 
                "Entry point of 0 cannot be automatically fixed.\n\n"
                "For DLLs, this may be intentional.\n"
                "For executables, you need to manually set the correct entry point RVA.\n\n"
                f"Offset: 0x{offset:X}")
            return
        
        elif "extends beyond file" in description.lower() or "truncated" in description.lower():
            # Can't auto-fix truncated files
            messagebox.showinfo("Cannot Auto-Fix", 
                "This error indicates the file is truncated or corrupted.\n\n"
                "The file data extends beyond the actual file size.\n"
                "This cannot be automatically fixed - you may need to recover the original file.\n\n"
                f"Offset: 0x{offset:X}")
            return
        
        elif "packer" in description.lower() or "suspicious" in description.lower():
            # Packer-related warnings - informational only
            messagebox.showinfo("Information", 
                "This warning indicates potential packer/protector usage.\n\n"
                "This is not necessarily an error - many legitimate programs use packers.\n"
                "No automatic fix is available for this.\n\n"
                f"Section at offset: 0x{offset:X}")
            return
        
        # ELF-specific fixes
        elif "ELF magic" in description.lower() or category == "ELF Magic":
            if messagebox.askyesno("Fix ELF Magic", 
                "This will write the ELF magic bytes (0x7F454C46) at offset 0x0.\n\nApply fix?"):
                self.data[0:4] = b'\x7fELF'
                fix_applied = True
                fix_description = "Fixed ELF magic signature at offset 0x0"
        
        elif "ELF class" in description.lower() or category == "ELF Class":
            result = messagebox.askquestion("Fix ELF Class", 
                "Invalid ELF class detected.\n\n"
                "Click YES for 64-bit (ELFCLASS64)\n"
                "Click NO for 32-bit (ELFCLASS32)\n"
                "Click CANCEL to abort",
                type=messagebox.YESNOCANCEL)
            if result == 'yes':
                self.data[4] = 2  # ELFCLASS64
                fix_applied = True
                fix_description = "Fixed ELF class to 64-bit at offset 0x4"
            elif result == 'no':
                self.data[4] = 1  # ELFCLASS32
                fix_applied = True
                fix_description = "Fixed ELF class to 32-bit at offset 0x4"
        
        elif "data encoding" in description.lower() or category == "Encoding":
            result = messagebox.askquestion("Fix ELF Encoding", 
                "Invalid ELF data encoding detected.\n\n"
                "Click YES for Little-endian (LSB)\n"
                "Click NO for Big-endian (MSB)\n"
                "Click CANCEL to abort",
                type=messagebox.YESNOCANCEL)
            if result == 'yes':
                self.data[5] = 1  # ELFDATA2LSB
                fix_applied = True
                fix_description = "Fixed ELF encoding to little-endian at offset 0x5"
            elif result == 'no':
                self.data[5] = 2  # ELFDATA2MSB
                fix_applied = True
                fix_description = "Fixed ELF encoding to big-endian at offset 0x5"
        
        elif "ELF version" in description.lower():
            if messagebox.askyesno("Fix ELF Version", 
                "This will set the ELF version to 1 (current) at offset 0x6.\n\nApply fix?"):
                self.data[6] = 1
                fix_applied = True
                fix_description = "Fixed ELF version to 1 at offset 0x6"
        
        else:
            # Unknown error type
            messagebox.showinfo("Cannot Auto-Fix", 
                f"No automatic fix available for this error.\n\n"
                f"Category: {category}\n"
                f"Description: {description}\n"
                f"Offset: 0x{offset:X}\n\n"
                "You can manually edit the bytes at this offset.")
            return
        
        if fix_applied:
            self.modified = True
            self.display_hex()
            self.highlight_offset(offset, 4)
            messagebox.showinfo("Fix Applied", f"{fix_description}\n\nFile marked as modified. Remember to save!")
            
            # Remove the fixed item from the tree
            tree.delete(item_id)
            
            # Optionally re-run error check
            if messagebox.askyesno("Re-check", "Would you like to re-run the error check to verify the fix?"):
                dialog.destroy()
                self.check_program_errors()
    
    def get_error_explanation(self, category, description):
        """Get detailed explanation for an error"""
        explanations = {
            "DOS Header": (
                "The DOS Header is the first part of a PE file.\n\n"
                "It contains the 'MZ' signature (bytes 0x4D5A) at the very beginning,\n"
                "and a pointer to the PE header at offset 0x3C.\n\n"
                "If the DOS header is invalid, Windows cannot recognize the file as executable."
            ),
            "PE Signature": (
                "The PE Signature is 'PE\\x00\\x00' (bytes 0x50450000).\n\n"
                "It marks the beginning of the PE header and is required for\n"
                "Windows to recognize the file as a valid executable.\n\n"
                "The location of this signature is specified in the DOS header at offset 0x3C."
            ),
            "Checksum": (
                "The PE Checksum is used to verify file integrity.\n\n"
                "While not strictly required for most executables,\n"
                "it is required for drivers and signed files.\n\n"
                "A checksum of 0 is common for unsigned executables but\n"
                "a mismatch indicates the file may have been modified."
            ),
            "Alignment": (
                "PE files have two alignment values:\n\n"
                "- Section Alignment: How sections are aligned in memory\n"
                "- File Alignment: How sections are aligned in the file\n\n"
                "Section alignment must be >= file alignment.\n"
                "File alignment should be a power of 2 between 512 and 64K."
            ),
            "Sections": (
                "PE sections contain the actual code and data.\n\n"
                "Each section has a name (like .text, .data, .rsrc),\n"
                "a virtual address, size, and characteristics.\n\n"
                "Section errors can indicate corruption or malicious modification."
            ),
            "Entry Point": (
                "The Entry Point is the RVA (Relative Virtual Address) where\n"
                "execution begins when the program is loaded.\n\n"
                "An entry point of 0 is valid for DLLs but suspicious for EXEs.\n"
                "An invalid entry point will cause the program to crash."
            ),
            "ELF Magic": (
                "The ELF Magic is the bytes 0x7F followed by 'ELF'.\n\n"
                "This signature identifies the file as an ELF (Executable and Linkable Format)\n"
                "file used on Linux and other Unix-like systems."
            ),
            "ELF Class": (
                "ELF Class indicates whether the file is 32-bit or 64-bit.\n\n"
                "1 = ELFCLASS32 (32-bit)\n"
                "2 = ELFCLASS64 (64-bit)\n\n"
                "This must match the target architecture."
            ),
            "Encoding": (
                "ELF Encoding specifies the byte order (endianness).\n\n"
                "1 = Little-endian (LSB) - used on x86/x64\n"
                "2 = Big-endian (MSB) - used on some RISC architectures"
            )
        }
        
        # Find matching explanation
        for key, explanation in explanations.items():
            if key.lower() in category.lower():
                return f"{explanation}\n\nCurrent issue:\n{description}"
        
        return f"Category: {category}\n\nDescription: {description}\n\nNo detailed explanation available for this error type."

    def find_ip_addresses(self):
        """Find IP addresses in the file"""
        import re
        ip_addresses = []
        
        # Convert data to string for regex search
        try:
            text = self.data.decode('ascii', errors='ignore')
        except:
            return ip_addresses
        
        # IPv4 pattern
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        
        for match in re.finditer(ip_pattern, text):
            ip_str = match.group()
            # Skip common false positives like version numbers
            if not ip_str.startswith('0.0.') and not ip_str.startswith('1.0.'):
                offset = match.start()
                ip_addresses.append((offset, ip_str))
        
        return ip_addresses
    
    def find_urls(self):
        """Find URLs in the file"""
        import re
        urls = []
        
        try:
            text = self.data.decode('ascii', errors='ignore')
        except:
            return urls
        
        # URL pattern
        url_pattern = r'https?://[^\s\x00-\x1f\x7f-\xff]+'
        
        for match in re.finditer(url_pattern, text):
            url_str = match.group()
            # Limit length for display
            if len(url_str) > 100:
                url_str = url_str[:100] + "..."
            offset = match.start()
            urls.append((offset, url_str))
        
        return urls
    
    def extract_nearby_network_info(self, pos):
        """Extract IP addresses or domains near a network-related pattern"""
        import re
        
        # Search 200 bytes before and after
        start = max(0, pos - 200)
        end = min(len(self.data), pos + 200)
        nearby = self.data[start:end]
        
        try:
            text = nearby.decode('ascii', errors='ignore')
        except:
            return None
        
        # Look for IP addresses
        ip_pattern = r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b'
        ip_match = re.search(ip_pattern, text)
        if ip_match:
            return ip_match.group()
        
        # Look for domain names
        domain_pattern = r'\b[a-z0-9][a-z0-9-]{0,61}[a-z0-9]?\.[a-z]{2,}\b'
        domain_match = re.search(domain_pattern, text, re.IGNORECASE)
        if domain_match:
            domain = domain_match.group()
            if '.' in domain and not domain.startswith('.') and not domain.endswith('.'):
                return domain
        
        return None
    
    def highlight_malware_offset(self, offset, length):
        """Highlight a malware detection in the hex view"""
        for i in range(length):
            current_offset = offset + i
            if current_offset >= len(self.data):
                break
            
            line = (current_offset // 16) + 1
            byte_in_line = current_offset % 16
            
            # Calculate hex column
            if byte_in_line < 8:
                col = 10 + byte_in_line * 3
            else:
                col = 10 + byte_in_line * 3 + 1
            
            # Highlight hex value
            self.text_widget.tag_add("malware", f"{line}.{col}", f"{line}.{col+2}")
            
            # Highlight ASCII character
            ascii_col = 61 + byte_in_line
            self.text_widget.tag_add("malware", f"{line}.{ascii_col}", f"{line}.{ascii_col+1}")
    
    def show_malware_results(self, detections):
        """Display malware scan results"""
        dialog = tk.Toplevel(self.root)
        dialog.title("Malware Scan Results")
        dialog.geometry("700x500")
        dialog.transient(self.root)
        
        if not detections:
            tk.Label(dialog, text="✓ No suspicious patterns detected", 
                    font=("Arial", 14, "bold"), fg="green").pack(pady=20)
            tk.Label(dialog, text="The file appears to be clean.", 
                    font=("Arial", 10)).pack(pady=10)
        else:
            tk.Label(dialog, text=f"⚠ Warning: {len(detections)} suspicious patterns found!", 
                    font=("Arial", 14, "bold"), fg="red").pack(pady=10)
            tk.Label(dialog, text="Highlighted in red in the hex view. This does not guarantee malware.", 
                    font=("Arial", 9), fg="#666").pack(pady=5)
            
            # Create listbox with scrollbar
            frame = tk.Frame(dialog)
            frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
            
            scrollbar = tk.Scrollbar(frame)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            
            listbox = tk.Listbox(frame, font=("Courier", 9), yscrollcommand=scrollbar.set)
            listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            scrollbar.config(command=listbox.yview)
            
            # Sort by offset
            detections.sort(key=lambda x: x['offset'])
            
            # Add detections to listbox
            for det in detections:
                line = f"0x{det['offset']:08X} - {det['description']}: {det['pattern']}"
                listbox.insert(tk.END, line)
            
            # Double-click to jump to location
            def on_double_click(event):
                selection = listbox.curselection()
                if selection:
                    idx = selection[0]
                    offset = detections[idx]['offset']
                    length = detections[idx]['length']
                    dialog.destroy()
                    
                    # Bring main window to front
                    self.root.lift()
                    self.root.focus_force()
                    
                    # Jump to and highlight the offset
                    self.highlight_offset(offset, length)
                    
                    # Ensure the text widget has focus
                    self.text_widget.focus_set()
            
            listbox.bind("<Double-Button-1>", on_double_click)
        
        tk.Button(dialog, text="Close", command=dialog.destroy, padx=20).pack(pady=10)
        
        status = "CLEAN" if not detections else f"{len(detections)} DETECTIONS"
        self.update_status(f"Malware scan complete: {status}")
        
        # Store detections and show navigation controls if found
        if detections:
            # Classify threat levels for each detection
            for det in detections:
                det['threat_level'] = self.classify_threat_level(det['description'], det['pattern'])
            
            # Store all detections and apply filter
            self.all_malware_detections = sorted(detections, key=lambda x: x['offset'])
            self.threat_filter_var.set('All Threats')
            self.update_threat_filter_options()
            self.apply_threat_filter()
            
            self.malware_nav_frame.pack(side=tk.LEFT, padx=10, pady=2)
            
            # Show explanation panel for first detection
            if self.malware_detections:
                first_detection = self.malware_detections[0]
                explanation = self.get_malware_explanation(first_detection['description'])
                self.malware_info_label.config(text=f"{first_detection['description']} - {explanation}")
                self.malware_info_frame.pack(side=tk.BOTTOM, fill=tk.X, before=self.status_bar)
                
                # Automatically open the further analysis dialog
                self.further_analyze_detection()
        else:
            self.clear_detections()
    
    def classify_threat_level(self, description, pattern):
        """Classify a detection into High, Moderate, or Low risk - matches Further Analysis logic"""
        description_lower = description.lower()
        pattern_lower = pattern.lower()
        
        # Get context around the detection for better classification
        # Find the offset for this detection
        offset = None
        for det in self.all_malware_detections if hasattr(self, 'all_malware_detections') else []:
            if det.get('description') == description and det.get('pattern') == pattern:
                offset = det.get('offset')
                break
        
        context_text = ""
        if offset is not None:
            context_start = max(0, offset - 200)
            context_end = min(len(self.data), offset + len(pattern) + 200)
            try:
                context_text = self.data[context_start:context_end].decode('ascii', errors='ignore').lower()
            except:
                pass
        
        # Check for IPs and URLs in context
        import re
        ips = re.findall(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', context_text)
        urls = re.findall(r'https?://[^\s]+', context_text)
        
        # High risk indicators (same as Further Analysis)
        high_risk_count = sum([
            'createremotethread' in description_lower or 'inject' in pattern_lower,
            'virtualallocex' in description_lower or 'writeprocessmemory' in description_lower,
            'ransom' in pattern_lower or 'crypt' in pattern_lower,
            'mimikatz' in pattern_lower,
            len(ips) > 0 and ('download' in context_text or 'send' in context_text),
            'sedebugprivilege' in description_lower,
            'keylogger' in description_lower or 'getasynckeystate' in description_lower or 'setwindowshook' in description_lower,
        ])
        
        # Moderate risk indicators (same as Further Analysis)
        moderate_risk_count = sum([
            'registry' in pattern_lower or 'reg add' in pattern_lower,
            'powershell' in pattern_lower or 'cmd.exe' in pattern_lower,
            'process' in description_lower,
            len(urls) > 0,
            'schedule' in pattern_lower or 'startup' in context_text,
            'loadlibrary' in description_lower or 'getprocaddress' in description_lower,
            'urldownloadtofile' in description_lower or 'internetopen' in description_lower,
            'socket' in description_lower or 'connect' in description_lower,
            description.startswith('IP Address:') or description.startswith('URL:'),
        ])
        
        # Match the Further Analysis thresholds exactly
        if high_risk_count >= 2:
            return 'high'  # 🔴 HIGH RISK
        elif high_risk_count >= 1:
            return 'high'  # 🟠 MODERATE-HIGH RISK (grouped with high for filtering)
        elif moderate_risk_count >= 2:
            return 'moderate'  # 🟡 MODERATE RISK
        else:
            return 'low'  # 🟢 LOW-MODERATE RISK
    
    def apply_threat_filter(self):
        """Apply the current threat filter to detections"""
        filter_value = self.threat_filter_var.get()
        
        if filter_value == 'All Threats':
            self.malware_detections = self.all_malware_detections.copy()
        elif filter_value == 'High Risk':
            self.malware_detections = [d for d in self.all_malware_detections if d.get('threat_level') == 'high']
        elif filter_value == 'Moderate Risk':
            self.malware_detections = [d for d in self.all_malware_detections if d.get('threat_level') == 'moderate']
        elif filter_value == 'Low Risk':
            self.malware_detections = [d for d in self.all_malware_detections if d.get('threat_level') == 'low']
        
        self.current_detection_index = 0 if self.malware_detections else -1
        self.update_detection_label()
        
        # Re-apply highlights based on filter
        self.text_widget.tag_remove("malware", 1.0, tk.END)
        for det in self.malware_detections:
            self.highlight_malware_offset(det['offset'], det['length'])
        
        # Update to first detection if available
        if self.malware_detections:
            detection = self.malware_detections[0]
            self.text_widget.tag_remove("highlight", 1.0, tk.END)
            self.highlight_offset(detection['offset'], detection['length'])
            explanation = self.get_malware_explanation(detection['description'])
            self.malware_info_label.config(text=f"{detection['description']} - {explanation}")
            if self.analysis_dialog and self.analysis_dialog.winfo_exists():
                self.update_analysis_content()
    
    def on_threat_filter_change(self, event=None):
        """Handle threat filter dropdown change"""
        self.apply_threat_filter()
        filter_value = self.threat_filter_var.get()
        total_all = len(self.all_malware_detections)
        total_filtered = len(self.malware_detections)
        self.update_status(f"Showing {total_filtered} of {total_all} detections ({filter_value})")
    
    def update_threat_filter_options(self):
        """Update threat filter dropdown to only show available threat levels"""
        if not hasattr(self, 'all_malware_detections') or not self.all_malware_detections:
            self.threat_filter['values'] = ['All Threats']
            self.threat_filter_var.set('All Threats')
            return
        
        # Count detections by threat level
        has_high = any(d.get('threat_level') == 'high' for d in self.all_malware_detections)
        has_moderate = any(d.get('threat_level') == 'moderate' for d in self.all_malware_detections)
        has_low = any(d.get('threat_level') == 'low' for d in self.all_malware_detections)
        
        # Build options list
        options = ['All Threats']
        if has_high:
            options.append('High Risk')
        if has_moderate:
            options.append('Moderate Risk')
        if has_low:
            options.append('Low Risk')
        
        self.threat_filter['values'] = options
        
        # If current selection is no longer valid, reset to All Threats
        if self.threat_filter_var.get() not in options:
            self.threat_filter_var.set('All Threats')

    def get_malware_explanation(self, description):
        """Get detailed explanation for a malware detection"""
        explanations = {
            "Command Prompt execution": "Executes Windows command prompt (cmd.exe). Used to run shell commands, often for system manipulation.",
            "PowerShell execution": "Executes PowerShell scripts. Can download files, modify system settings, or execute arbitrary code.",
            "DLL execution": "Runs Dynamic Link Libraries using rundll32.exe. Commonly used to execute malicious DLLs.",
            "Register DLL": "Registers DLL files in the system. Can install malicious components persistently.",
            "Task scheduler": "Creates scheduled tasks using schtasks. Used for persistence to run malware at system startup.",
            "Network configuration": "Modifies network settings using netsh. Can disable firewall or change network routing.",
            "User enumeration": "Checks current user identity. Often used to determine privilege level before attacks.",
            "Process termination": "Kills running processes. Used to disable antivirus or security software.",
            "Registry modification": "Adds registry keys. Common for persistence, startup execution, or disabling security features.",
            "Registry deletion": "Deletes registry entries. Can remove security settings or traces of malware.",
            "Registry access": "Accesses user-specific registry. May modify startup programs or user settings.",
            "System registry access": "Accesses system-wide registry. Can change global settings, disable security features.",
            "Debug privilege escalation": "Requests debug privileges. Allows reading/writing memory of other processes.",
            "Code injection": "Creates threads in other processes. Primary technique for injecting malicious code.",
            "Memory allocation (injection)": "Allocates memory in other processes. Preparation for code injection attacks.",
            "Process memory write": "Writes to another process's memory. Used to inject code or modify program behavior.",
            "DLL loading": "Dynamically loads libraries. Can load malicious DLLs at runtime.",
            "Function address retrieval": "Gets addresses of functions. Used to call Windows APIs dynamically to evade detection.",
            "Execute command": "Executes shell commands. Can run arbitrary programs or scripts.",
            "Execute program": "Starts new programs. Legacy method to execute files.",
            "Process creation": "Creates new processes. Used to spawn malicious programs or downloaders.",
            "Download file": "Downloads files from internet. Common in droppers that fetch additional malware.",
            "Internet connection": "Opens internet connections. First step for network communication.",
            "HTTP request": "Sends HTTP requests. Used for command & control (C2) communication.",
            "Network socket": "Creates network sockets. Low-level network communication.",
            "Network connection": "Connects to remote servers. Used for data exfiltration or C2 communication.",
            "Send data": "Sends data over network. May exfiltrate stolen information.",
            "Receive data": "Receives network data. May download commands or additional payloads.",
            "Keyboard simulation": "Simulates keyboard input. Can automate actions or log keystrokes.",
            "Mouse simulation": "Simulates mouse clicks. Used to automate UI interactions.",
            "Keylogger indicator": "Monitors keyboard state. Primary function for keylogging malware.",
            "Keyboard/mouse hook": "Hooks keyboard/mouse events. Captures all user input (keylogger).",
            "Encryption (ransomware)": "Encrypts data. Primary function of ransomware.",
            "Decryption": "Decrypts data. May decrypt payload or configuration.",
            "Cryptocurrency": "References cryptocurrency. May be mining malware or wallet stealer.",
            "Cryptocurrency wallet": "Accesses crypto wallets. Attempts to steal cryptocurrency.",
            "Ransomware indicator": "Contains ransom-related strings. Likely ransomware demanding payment.",
            "Tor network": "Uses Tor .onion addresses. Anonymous C2 communication, hard to trace.",
            "Credential dumping tool": "Mimikatz - extracts passwords from memory. Used to steal credentials.",
            "Password access": "Accesses password data. May steal stored passwords.",
            "Admin access": "References admin privileges. Attempting privilege escalation.",
            "Privilege escalation": "Attempts to gain higher privileges. Trying to become administrator.",
            "Embedded PE file": "Contains another executable inside. May unpack or drop additional malware.",
            "Embedded ZIP/JAR": "Contains compressed archive. May extract hidden malware components.",
            "Call instruction (shellcode)": "x86 CALL instruction pattern. Common in shellcode for function calls.",
            "Common function prologue": "Standard function entry code. May indicate injected shellcode.",
        }
        
        # Check for pattern matches in description
        for key, explanation in explanations.items():
            if key in description:
                return explanation
        
        # Handle IP and URL detections
        if description.startswith("IP Address:"):
            return "Hard-coded IP address found. May be a command & control server or exfiltration target."
        elif description.startswith("URL:"):
            return "Hard-coded URL found. May be used for downloading payloads, C2 communication, or data exfiltration."
        
        return "Suspicious pattern detected. Review the context to determine if this is malicious behavior."
    
    def update_detection_label(self):
        """Update the detection counter label"""
        if self.malware_detections:
            total = len(self.malware_detections)
            current = self.current_detection_index + 1 if self.current_detection_index >= 0 else 0
            self.detection_label.config(text=f"{current}/{total}")
        else:
            self.detection_label.config(text="0/0")
    
    def get_best_encoding_for_detection(self, offset, length):
        """Determine the best encoding to view a detection - optimized version"""
        # Smaller context for speed (50 bytes each side)
        context_start = max(0, offset - 50)
        context_end = min(len(self.data), offset + length + 50)
        context_data = self.data[context_start:context_end]
        data_len = len(context_data)
        
        if data_len == 0:
            return 'ASCII'
        
        # Single pass through data to collect statistics
        null_count = 0
        odd_nulls = 0
        even_nulls = 0
        high_bytes = 0
        cp1252_chars = 0
        cyrillic_chars = 0
        dos_chars = 0
        has_backslash_x = False
        
        for i, b in enumerate(context_data):
            if b == 0:
                null_count += 1
                if i % 2 == 1:
                    odd_nulls += 1
                else:
                    even_nulls += 1
            if b > 127:
                high_bytes += 1
                if 128 <= b <= 159:
                    cp1252_chars += 1
                if 128 <= b <= 175 or 224 <= b <= 239:
                    cyrillic_chars += 1
                if 176 <= b <= 223:
                    dos_chars += 1
            # Check for \x pattern
            if b == 92 and i + 1 < data_len and context_data[i + 1] == 120:  # '\' followed by 'x'
                has_backslash_x = True
        
        # UTF-16 detection (fastest check first since it's common in Windows)
        if null_count > data_len * 0.3:
            threshold = data_len // 4
            if odd_nulls > even_nulls and odd_nulls > threshold:
                return 'UTF-16LE'
            elif even_nulls > odd_nulls and even_nulls > threshold:
                return 'UTF-16BE'
        
        # Hex escaped shellcode pattern
        if has_backslash_x:
            return 'Hex Escaped'
        
        # Cyrillic check
        if cyrillic_chars > data_len * 0.1:
            return 'CP866 (DOS Cyrillic)'
        
        # DOS box drawing
        if dos_chars > data_len * 0.05:
            return 'CP437 (DOS)'
        
        # High ASCII check
        if high_bytes > data_len * 0.1:
            if cp1252_chars > 0:
                return 'CP1252'
            return 'Latin-1'
        
        # Default to ASCII
        return 'ASCII'
    
    def next_detection(self):
        """Navigate to next malware detection"""
        if not self.malware_detections:
            return
        
        self.current_detection_index = (self.current_detection_index + 1) % len(self.malware_detections)
        detection = self.malware_detections[self.current_detection_index]
        
        # Auto-select best encoding for this detection (if enabled)
        best_encoding = self.current_encoding
        if self.auto_select_encoding.get():
            best_encoding = self.get_best_encoding_for_detection(detection['offset'], detection['length'])
            if best_encoding != self.current_encoding:
                self.current_encoding = best_encoding
                self.encoding_var.set(best_encoding)
                self.display_hex()
                # Re-apply malware highlights after display refresh
                for det in self.malware_detections:
                    self.highlight_malware_offset(det['offset'], det['length'])
        
        # Clear highlight tag and re-highlight current
        self.text_widget.tag_remove("highlight", 1.0, tk.END)
        self.highlight_offset(detection['offset'], detection['length'])
        self.update_detection_label()
        
        # Show explanation panel
        explanation = self.get_malware_explanation(detection['description'])
        self.malware_info_label.config(text=f"{detection['description']} - {explanation}")
        self.malware_info_frame.pack(side=tk.BOTTOM, fill=tk.X, before=self.status_bar)
        
        # Update analysis dialog if it's open
        if self.analysis_dialog and self.analysis_dialog.winfo_exists():
            self.update_analysis_content()
        
        # Update status with detection info
        self.update_status(f"Detection {self.current_detection_index + 1}/{len(self.malware_detections)}: {detection['description']} [Encoding: {best_encoding}]")
    
    def prev_detection(self):  
        """Navigate to previous malware detection"""
        if not self.malware_detections:
            return
        
        self.current_detection_index = (self.current_detection_index - 1) % len(self.malware_detections)
        detection = self.malware_detections[self.current_detection_index]
        
        # Auto-select best encoding for this detection (if enabled)
        best_encoding = self.current_encoding
        if self.auto_select_encoding.get():
            best_encoding = self.get_best_encoding_for_detection(detection['offset'], detection['length'])
            if best_encoding != self.current_encoding:
                self.current_encoding = best_encoding
                self.encoding_var.set(best_encoding)
                self.display_hex()
                # Re-apply malware highlights after display refresh
                for det in self.malware_detections:
                    self.highlight_malware_offset(det['offset'], det['length'])
        
        # Clear highlight tag and re-highlight current
        self.text_widget.tag_remove("highlight", 1.0, tk.END)
        self.highlight_offset(detection['offset'], detection['length'])
        self.update_detection_label()
        
        # Show explanation panel
        explanation = self.get_malware_explanation(detection['description'])
        self.malware_info_label.config(text=f"{detection['description']} - {explanation}")
        self.malware_info_frame.pack(side=tk.BOTTOM, fill=tk.X, before=self.status_bar)
        
        # Update analysis dialog if it's open
        if self.analysis_dialog and self.analysis_dialog.winfo_exists():
            self.update_analysis_content()
        
        # Update status with detection info
        self.update_status(f"Detection {self.current_detection_index + 1}/{len(self.malware_detections)}: {detection['description']} [Encoding: {best_encoding}]")
    
    def update_analysis_content(self):
        """Update the analysis content for the current detection"""
        if not self.malware_detections or self.current_detection_index < 0:
            return
        if not self.analysis_text_widget or not self.analysis_dialog:
            return
        
        detection = self.malware_detections[self.current_detection_index]
        offset = detection['offset']
        pattern = detection['pattern']
        description = detection['description']
        
        # Update dialog title
        if self.analysis_dialog.winfo_exists():
            self.analysis_dialog.title(f"Further Analysis - Detection at 0x{offset:08X}")
        
        # Extract context (500 bytes before and after)
        context_start = max(0, offset - 500)
        context_end = min(len(self.data), offset + len(pattern) + 500)
        context_data = self.data[context_start:context_end]
        
        # Try to decode as ASCII with errors ignored
        try:
            context_text = context_data.decode('ascii', errors='ignore')
        except:
            context_text = ""
        
        # Analyze the context
        analysis_parts = [f"🔍 DETAILED ANALYSIS\n\nDetection: {description}\nPattern: {pattern}\nOffset: 0x{offset:08X}\n"]
        
        # Look for related patterns
        related_findings = []
        
        # Check for file paths
        import re
        file_paths = re.findall(r'[A-Za-z]:\\(?:[^\\/:*?"<>|\r\n]+\\)*[^\\/:*?"<>|\r\n]*', context_text)
        if file_paths:
            related_findings.append(f"📁 File paths found: {', '.join(set(file_paths[:3]))}")
        
        # Check for URLs in context
        urls = re.findall(r'https?://[^\s\x00-\x1f]+', context_text)
        if urls:
            related_findings.append(f"🌐 URLs nearby: {', '.join(set(urls[:3]))}")
        
        # Check for IP addresses in context
        ips = re.findall(r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', context_text)
        if ips:
            related_findings.append(f"📡 IP addresses nearby: {', '.join(set(ips[:3]))}")
        
        # Check for registry keys
        reg_keys = re.findall(r'HKEY_[A-Z_]+\\[^\\]+(?:\\[^\\]+)*', context_text)
        if reg_keys:
            related_findings.append(f"🔑 Registry keys: {', '.join(set(reg_keys[:2]))}")
        
        # Check for other suspicious strings nearby
        suspicious_nearby = []
        suspicious_checks = [
            (b'cmd.exe', 'Command execution'),
            (b'powershell', 'PowerShell'),
            (b'download', 'Download capability'),
            (b'execute', 'Execution'),
            (b'inject', 'Code injection'),
            (b'process', 'Process manipulation'),
            (b'thread', 'Thread creation'),
            (b'registry', 'Registry access'),
            (b'privilege', 'Privilege escalation'),
            (b'admin', 'Admin access'),
            (b'password', 'Password access'),
            (b'crypt', 'Encryption/Decryption'),
            (b'socket', 'Network socket'),
            (b'connect', 'Network connection'),
        ]
        
        for check_pattern, check_desc in suspicious_checks:
            if check_pattern in context_data.lower() and check_pattern.decode('ascii', errors='ignore').lower() not in pattern.lower():
                suspicious_nearby.append(check_desc)
        
        if suspicious_nearby:
            related_findings.append(f"⚠️  Related threats nearby: {', '.join(set(suspicious_nearby[:5]))}")
        
        # Build threat assessment
        threat_level = "UNKNOWN"
        threat_assessment = ""
        
        # Assess threat level based on context
        high_risk_indicators = sum([
            'CreateRemoteThread' in description or 'inject' in pattern.lower(),
            'VirtualAllocEx' in description or 'WriteProcessMemory' in description,
            'ransom' in pattern.lower() or 'crypt' in pattern.lower(),
            'mimikatz' in pattern.lower(),
            len(ips) > 0 and ('download' in context_text.lower() or 'send' in context_text.lower()),
            'SeDebugPrivilege' in description,
        ])
        
        medium_risk_indicators = sum([
            'registry' in pattern.lower() or 'reg add' in pattern.lower(),
            'powershell' in pattern.lower() or 'cmd.exe' in pattern.lower(),
            'process' in description.lower(),
            len(urls) > 0,
            'schedule' in pattern.lower() or 'startup' in context_text.lower(),
        ])
        
        if high_risk_indicators >= 2:
            threat_level = "🔴 HIGH RISK"
            threat_assessment = "This pattern suggests active malicious behavior such as code injection, memory manipulation, or data exfiltration. Likely part of an active attack or trojan."
        elif high_risk_indicators >= 1:
            threat_level = "🟠 MODERATE-HIGH RISK"
            threat_assessment = "This pattern indicates potentially dangerous capabilities. May be used for privilege escalation, code injection, or system compromise."
        elif medium_risk_indicators >= 2:
            threat_level = "🟡 MODERATE RISK"
            threat_assessment = "This pattern shows suspicious behavior that could be used maliciously. Common in malware but may also appear in legitimate software."
        else:
            threat_level = "🟢 LOW-MODERATE RISK"
            threat_assessment = "This pattern is suspicious but relatively common. Could be legitimate functionality or part of a larger malicious payload."
        
        # Determine likely malware type
        malware_types = []
        if 'crypt' in pattern.lower() and 'ransom' in context_text.lower():
            malware_types.append("💰 Ransomware - encrypts files for ransom")
        if 'keylogger' in description.lower() or 'GetAsyncKeyState' in description or 'SetWindowsHook' in description:
            malware_types.append("⌨️ Keylogger - captures keyboard input")
        if 'inject' in description.lower() or 'CreateRemoteThread' in description:
            malware_types.append("💉 Code Injector - injects malicious code into processes")
        if len(ips) > 0 or len(urls) > 0:
            if 'send' in context_text.lower() or 'upload' in context_text.lower():
                malware_types.append("📤 Data Exfiltrator - steals and transmits data")
            else:
                malware_types.append("📥 Downloader/C2 - communicates with remote server")
        if 'mimikatz' in pattern.lower() or 'password' in pattern.lower():
            malware_types.append("🔓 Credential Stealer - harvests passwords")
        if 'bitcoin' in pattern.lower() or 'wallet' in pattern.lower():
            malware_types.append("⛏️ Cryptominer/Wallet Stealer")
        if 'reg add' in pattern.lower() or 'schtasks' in pattern.lower() or 'startup' in context_text.lower():
            malware_types.append("🔄 Persistence Mechanism - maintains presence on system")
        
        # Build final analysis
        analysis_parts.append(f"\n{'='*60}\n")
        analysis_parts.append(f"THREAT LEVEL: {threat_level}\n\n")
        analysis_parts.append(f"Assessment: {threat_assessment}\n\n")
        
        if malware_types:
            analysis_parts.append(f"Likely Malware Type(s):\n")
            for mtype in malware_types:
                analysis_parts.append(f"  • {mtype}\n")
            analysis_parts.append("\n")
        
        if related_findings:
            analysis_parts.append(f"Context Analysis:\n")
            for finding in related_findings:
                analysis_parts.append(f"  • {finding}\n")
            analysis_parts.append("\n")
        
        # Recommendations
        analysis_parts.append(f"{'='*60}\n")
        analysis_parts.append("Recommendations:\n")
        if threat_level.startswith("🔴"):
            analysis_parts.append("  ⚠️  IMMEDIATE ACTION REQUIRED\n")
            analysis_parts.append("  • Isolate this file immediately\n")
            analysis_parts.append("  • Do NOT execute this file\n")
            analysis_parts.append("  • Submit to antivirus vendor for analysis\n")
        elif threat_level.startswith("🟠"):
            analysis_parts.append("  ⚠️  Exercise extreme caution\n")
            analysis_parts.append("  • Verify file source and legitimacy\n")
            analysis_parts.append("  • Scan with multiple antivirus engines\n")
            analysis_parts.append("  • Consider sandbox analysis\n")
        else:
            analysis_parts.append("  • Verify this is from a trusted source\n")
            analysis_parts.append("  • Compare with known good versions\n")
            analysis_parts.append("  • Review other detections in the file\n")
        
        # Update the text widget with analysis
        if self.analysis_text_widget:
            self.analysis_text_widget.config(state=tk.NORMAL)
            self.analysis_text_widget.delete(1.0, tk.END)
            self.analysis_text_widget.insert(1.0, ''.join(analysis_parts))
            self.analysis_text_widget.config(state=tk.DISABLED)
    
    def further_analyze_detection(self):
        """Open or update the analysis dialog"""
        if not self.malware_detections or self.current_detection_index < 0:
            return
        
        # If dialog already exists and is visible, just update it
        if self.analysis_dialog and self.analysis_dialog.winfo_exists():
            self.update_analysis_content()
            self.analysis_dialog.lift()
            return
        
        # Create new dialog
        detection = self.malware_detections[self.current_detection_index]
        offset = detection['offset']
        
        self.analysis_dialog = tk.Toplevel(self.root)
        self.analysis_dialog.title(f"Further Analysis - Detection at 0x{offset:08X}")
        self.analysis_dialog.geometry("700x600")
        self.analysis_dialog.transient(self.root)
        
        # Add info label
        info_frame = tk.Frame(self.analysis_dialog, bg="#e3f2fd", relief=tk.RAISED, borderwidth=1)
        info_frame.pack(fill=tk.X, padx=5, pady=5)
        tk.Label(info_frame, text="💡 Tip: Use Next/Prev or F3/Shift+F3 to navigate detections. Analysis updates automatically.", 
                font=("Arial", 8), bg="#e3f2fd", fg="#1565c0").pack(side=tk.LEFT, padx=5, pady=5)
        
        # Auto-encoding toggle checkbox
        tk.Checkbutton(info_frame, text="Auto-select encoding", variable=self.auto_select_encoding,
                      bg="#e3f2fd", fg="#1565c0", font=("Arial", 8), 
                      activebackground="#e3f2fd", selectcolor="#bbdefb").pack(side=tk.RIGHT, padx=10, pady=5)
        
        self.analysis_text_widget = scrolledtext.ScrolledText(self.analysis_dialog, font=("Courier", 9), wrap=tk.WORD)
        self.analysis_text_widget.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Populate with initial analysis
        self.update_analysis_content()
        
        def on_close():
            dialog = self.analysis_dialog
            self.analysis_dialog = None
            self.analysis_text_widget = None
            if dialog:
                dialog.destroy()
        
        self.analysis_dialog.protocol("WM_DELETE_WINDOW", on_close)
        
        # Button frame
        button_frame = tk.Frame(self.analysis_dialog)
        button_frame.pack(pady=10)
        
        tk.Button(button_frame, text="📊 Analyze Entropy", command=self.analyze_entropy, 
                 bg="#2196F3", fg="white", font=("Arial", 9, "bold"), padx=15, pady=5).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="🔤 Best Encoding", command=self.apply_best_encoding, 
                 bg="#4CAF50", fg="white", font=("Arial", 9, "bold"), padx=15, pady=5).pack(side=tk.LEFT, padx=5)
        tk.Button(button_frame, text="Close", command=on_close, padx=20).pack(side=tk.LEFT, padx=5)
    
    def apply_best_encoding(self):
        """Apply the best encoding for the current detection"""
        if not self.malware_detections or self.current_detection_index < 0:
            return
        
        detection = self.malware_detections[self.current_detection_index]
        best_encoding = self.get_best_encoding_for_detection(detection['offset'], detection['length'])
        
        if best_encoding != self.current_encoding:
            self.current_encoding = best_encoding
            self.encoding_var.set(best_encoding)
            self.display_hex()
            # Re-apply malware highlights after display refresh
            for det in self.malware_detections:
                self.highlight_malware_offset(det['offset'], det['length'])
            # Re-highlight current detection
            self.text_widget.tag_remove("highlight", 1.0, tk.END)
            self.highlight_offset(detection['offset'], detection['length'])
            self.update_status(f"Encoding changed to: {best_encoding}")
        else:
            self.update_status(f"Already using best encoding: {best_encoding}")
    
    def analyze_entropy(self):
        """Calculate and display entropy for the detected threat"""
        if not self.malware_detections or self.current_detection_index < 0:
            return
            
        detection = self.malware_detections[self.current_detection_index]
        offset = detection['offset']
        length = detection['length']
        
        # Get context (threat + surrounding bytes)
        context_start = max(0, offset - 100)
        context_end = min(len(self.data), offset + length + 100)
        threat_data = self.data[offset:offset+length]
        context_data = self.data[context_start:context_end]
        
        def calculate_shannon_entropy(data):
            if not data:
                return 0
            entropy = 0
            for x in range(256):
                p_x = data.count(x) / len(data)
                if p_x > 0:
                    entropy += - p_x * math.log2(p_x)
            return entropy
            
        threat_entropy = calculate_shannon_entropy(threat_data)
        context_entropy = calculate_shannon_entropy(context_data)
        
        # Interpret results
        interpretation = ""
        if threat_entropy > 7.5:
            interpretation = "Extremely High (Likely Encrypted/Compressed)"
        elif threat_entropy > 6.5:
            interpretation = "High (Possible Obfuscation)"
        elif threat_entropy > 5.0:
            interpretation = "Moderate (Typical Code/Data)"
        else:
            interpretation = "Low (Text/Padding)"
            
        # Show results
        messagebox.showinfo("Entropy Analysis", 
            f"Threat Entropy: {threat_entropy:.4f}\n"
            f"Context Entropy: {context_entropy:.4f}\n\n"
            f"Interpretation: {interpretation}\n\n"
            f"Note: High entropy often indicates packed or encrypted data used to hide malicious code.")

    def clear_detections(self):
        """Clear all malware detections and hide navigation controls"""
        self.malware_detections = []
        self.all_malware_detections = []
        self.current_detection_index = -1
        self.malware_nav_frame.pack_forget()
        self.malware_info_frame.pack_forget()
        self.text_widget.tag_remove("malware", 1.0, tk.END)
        self.text_widget.tag_remove("highlight", 1.0, tk.END)
        self.update_detection_label()
        self.threat_filter_var.set('All Threats')
        self.update_threat_filter_options()
    
    def show_malware_analysis_tools(self):
        """Show comprehensive malware analysis tools window"""
        if not self.data:
            messagebox.showwarning("No File", "Please open a file first.")
            return
        
        # Create analysis window
        analysis_win = tk.Toplevel(self.root)
        analysis_win.title("🔬 Malware Analysis Tools")
        analysis_win.geometry("900x700")
        analysis_win.transient(self.root)
        
        # Keep window open checkbox variable
        keep_open_var = tk.BooleanVar(value=True)
        
        # Create notebook (tabbed interface)
        notebook = ttk.Notebook(analysis_win)
        notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        # Style configuration
        style = ttk.Style()
        style.configure('Analysis.TFrame', background='#f5f5f5')
        
        # ===== TAB 1: File Hashes =====
        hash_frame = ttk.Frame(notebook)
        notebook.add(hash_frame, text="📋 File Hashes")
        
        hash_header = tk.Frame(hash_frame, bg="#1976D2", height=50)
        hash_header.pack(fill=tk.X)
        hash_header.pack_propagate(False)
        tk.Label(hash_header, text="🔐 File Hash Calculator", font=("Arial", 14, "bold"), 
                bg="#1976D2", fg="white").pack(side=tk.LEFT, padx=15, pady=10)
        
        hash_content = tk.Frame(hash_frame, bg="#fafafa")
        hash_content.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Calculate hashes
        md5_hash = hashlib.md5(self.data).hexdigest()
        sha1_hash = hashlib.sha1(self.data).hexdigest()
        sha256_hash = hashlib.sha256(self.data).hexdigest()
        
        hash_info = [
            ("MD5", md5_hash, "#e3f2fd"),
            ("SHA-1", sha1_hash, "#e8f5e9"),
            ("SHA-256", sha256_hash, "#fff3e0"),
        ]
        
        for name, value, color in hash_info:
            frame = tk.Frame(hash_content, bg=color, relief=tk.RAISED, borderwidth=1)
            frame.pack(fill=tk.X, pady=5)
            tk.Label(frame, text=f"{name}:", font=("Arial", 10, "bold"), bg=color, width=10, anchor='w').pack(side=tk.LEFT, padx=10, pady=10)
            entry = tk.Entry(frame, font=("Courier", 10), width=70, relief=tk.FLAT)
            entry.insert(0, value)
            entry.config(state='readonly')
            entry.pack(side=tk.LEFT, padx=5, pady=10, fill=tk.X, expand=True)
            tk.Button(frame, text="📋 Copy", command=lambda v=value: self.copy_to_clipboard(v),
                     bg="#2196F3", fg="white", font=("Arial", 8)).pack(side=tk.RIGHT, padx=10, pady=10)
        
        # VirusTotal link
        vt_frame = tk.Frame(hash_content, bg="#ffebee", relief=tk.RAISED, borderwidth=1)
        vt_frame.pack(fill=tk.X, pady=15)
        tk.Label(vt_frame, text="🔍 VirusTotal Lookup:", font=("Arial", 10, "bold"), bg="#ffebee").pack(side=tk.LEFT, padx=10, pady=10)
        vt_url = f"https://www.virustotal.com/gui/file/{sha256_hash}"
        vt_entry = tk.Entry(vt_frame, font=("Courier", 9), width=50, relief=tk.FLAT)
        vt_entry.insert(0, vt_url)
        vt_entry.config(state='readonly')
        vt_entry.pack(side=tk.LEFT, padx=5, pady=10)
        tk.Button(vt_frame, text="🌐 Open in Browser", command=lambda: webbrowser.open(vt_url),
                 bg="#4CAF50", fg="white", font=("Arial", 8)).pack(side=tk.RIGHT, padx=5, pady=10)
        tk.Button(vt_frame, text="📋 Copy URL", command=lambda: self.copy_to_clipboard(vt_url),
                 bg="#f44336", fg="white", font=("Arial", 8)).pack(side=tk.RIGHT, padx=5, pady=10)
        
        # File size info
        size_frame = tk.Frame(hash_content, bg="#e0e0e0", relief=tk.RAISED, borderwidth=1)
        size_frame.pack(fill=tk.X, pady=5)
        file_size = len(self.data)
        tk.Label(size_frame, text=f"📁 File Size: {file_size:,} bytes ({file_size/1024:.2f} KB)", 
                font=("Arial", 10), bg="#e0e0e0").pack(side=tk.LEFT, padx=10, pady=10)
        
        # ===== TAB 2: String Extraction =====
        strings_frame = ttk.Frame(notebook)
        notebook.add(strings_frame, text="📝 Strings")
        
        strings_header = tk.Frame(strings_frame, bg="#388E3C", height=50)
        strings_header.pack(fill=tk.X)
        strings_header.pack_propagate(False)
        tk.Label(strings_header, text="📝 Extracted Strings", font=("Arial", 14, "bold"), 
                bg="#388E3C", fg="white").pack(side=tk.LEFT, padx=15, pady=10)
        
        # Controls
        strings_ctrl = tk.Frame(strings_frame, bg="#e8f5e9")
        strings_ctrl.pack(fill=tk.X, padx=10, pady=5)
        
        tk.Label(strings_ctrl, text="Min length:", bg="#e8f5e9").pack(side=tk.LEFT, padx=5)
        min_len_var = tk.StringVar(value="4")
        min_len_spin = tk.Spinbox(strings_ctrl, from_=3, to=20, width=5, textvariable=min_len_var)
        min_len_spin.pack(side=tk.LEFT, padx=5)
        
        strings_filter_var = tk.StringVar(value="All")
        tk.Label(strings_ctrl, text="Filter:", bg="#e8f5e9").pack(side=tk.LEFT, padx=(20,5))
        filter_combo = ttk.Combobox(strings_ctrl, textvariable=strings_filter_var, 
                                   values=["All", "URLs/IPs", "File Paths", "Registry", "Suspicious"],
                                   state='readonly', width=12)
        filter_combo.pack(side=tk.LEFT, padx=5)
        
        strings_search_var = tk.StringVar()
        tk.Label(strings_ctrl, text="Search:", bg="#e8f5e9").pack(side=tk.LEFT, padx=(20,5))
        tk.Entry(strings_ctrl, textvariable=strings_search_var, width=20).pack(side=tk.LEFT, padx=5)
        
        # Strings listbox with scrollbar
        strings_list_frame = tk.Frame(strings_frame)
        strings_list_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        strings_scrolly = tk.Scrollbar(strings_list_frame)
        strings_scrolly.pack(side=tk.RIGHT, fill=tk.Y)
        strings_scrollx = tk.Scrollbar(strings_list_frame, orient=tk.HORIZONTAL)
        strings_scrollx.pack(side=tk.BOTTOM, fill=tk.X)
        
        strings_tree = ttk.Treeview(strings_list_frame, columns=("offset", "type", "string"), show="headings",
                                   yscrollcommand=strings_scrolly.set, xscrollcommand=strings_scrollx.set)
        strings_tree.heading("offset", text="Offset")
        strings_tree.heading("type", text="Type")
        strings_tree.heading("string", text="String")
        strings_tree.column("offset", width=100)
        strings_tree.column("type", width=80)
        strings_tree.column("string", width=600)
        strings_tree.pack(fill=tk.BOTH, expand=True)
        strings_scrolly.config(command=strings_tree.yview)
        strings_scrollx.config(command=strings_tree.xview)
        
        # String count label
        strings_count_label = tk.Label(strings_frame, text="", font=("Arial", 9), bg="#e8f5e9")
        strings_count_label.pack(fill=tk.X, padx=10, pady=5)
        
        def extract_strings():
            strings_tree.delete(*strings_tree.get_children())
            min_len = int(min_len_var.get())
            filter_type = strings_filter_var.get()
            search_term = strings_search_var.get().lower()
            
            # Extract ASCII strings
            ascii_pattern = rb'[\x20-\x7e]{' + str(min_len).encode() + rb',}'
            extracted = []
            
            for match in re.finditer(ascii_pattern, self.data):
                s = match.group().decode('ascii', errors='ignore')
                offset = match.start()
                
                # Classify string type
                s_lower = s.lower()
                str_type = "ASCII"
                if re.search(r'https?://', s_lower) or re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', s):
                    str_type = "URL/IP"
                elif re.search(r'[a-z]:\\|\\\\|/usr/|/etc/', s_lower):
                    str_type = "Path"
                elif re.search(r'hkey_|\\software\\|\\system\\', s_lower):
                    str_type = "Registry"
                elif re.search(r'password|credential|token|secret|api.?key|encrypt|decrypt|shell|exec|cmd|powershell', s_lower):
                    str_type = "Suspicious"
                
                extracted.append((offset, str_type, s))
            
            # Extract Unicode strings
            unicode_pattern = rb'(?:[\x20-\x7e]\x00){' + str(min_len).encode() + rb',}'
            for match in re.finditer(unicode_pattern, self.data):
                try:
                    s = match.group().decode('utf-16le', errors='ignore')
                    if len(s) >= min_len:
                        offset = match.start()
                        s_lower = s.lower()
                        str_type = "Unicode"
                        if re.search(r'https?://', s_lower) or re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b', s):
                            str_type = "URL/IP"
                        elif re.search(r'[a-z]:\\|\\\\', s_lower):
                            str_type = "Path"
                        elif re.search(r'hkey_|\\software\\|\\system\\', s_lower):
                            str_type = "Registry"
                        elif re.search(r'password|credential|token|secret|api.?key|encrypt|decrypt|shell|exec|cmd|powershell', s_lower):
                            str_type = "Suspicious"
                        extracted.append((offset, str_type, s))
                except:
                    pass
            
            # Sort by offset
            extracted.sort(key=lambda x: x[0])
            
            # Apply filters
            filtered = []
            for offset, str_type, s in extracted:
                # Filter by type
                if filter_type != "All":
                    if filter_type == "URLs/IPs" and str_type != "URL/IP":
                        continue
                    elif filter_type == "File Paths" and str_type != "Path":
                        continue
                    elif filter_type == "Registry" and str_type != "Registry":
                        continue
                    elif filter_type == "Suspicious" and str_type != "Suspicious":
                        continue
                
                # Filter by search term
                if search_term and search_term not in s.lower():
                    continue
                
                filtered.append((offset, str_type, s))
            
            # Add to tree
            for offset, str_type, s in filtered[:5000]:  # Limit to 5000 for performance
                tag = ""
                if str_type == "Suspicious":
                    tag = "suspicious"
                elif str_type == "URL/IP":
                    tag = "url"
                elif str_type == "Registry":
                    tag = "registry"
                strings_tree.insert("", tk.END, values=(f"0x{offset:08X}", str_type, s), tags=(tag,))
            
            strings_tree.tag_configure("suspicious", background="#ffcdd2")
            strings_tree.tag_configure("url", background="#fff9c4")
            strings_tree.tag_configure("registry", background="#e1bee7")
            
            total = len(extracted)
            shown = len(filtered)
            strings_count_label.config(text=f"Total: {total} strings | Showing: {min(shown, 5000)} strings")
        
        tk.Button(strings_ctrl, text="🔍 Extract", command=extract_strings, bg="#4CAF50", fg="white").pack(side=tk.LEFT, padx=10)
        
        def on_string_double_click(event):
            selection = strings_tree.selection()
            if selection:
                item = strings_tree.item(selection[0])
                offset_str = item['values'][0]
                offset = int(offset_str, 16)
                if not keep_open_var.get():
                    analysis_win.destroy()
                self.highlight_offset(offset, len(item['values'][2]))
        
        strings_tree.bind("<Double-Button-1>", on_string_double_click)
        
        # Auto-extract on tab switch
        extract_strings()
        
        # ===== TAB 3: Import Analysis (PE files) =====
        imports_frame = ttk.Frame(notebook)
        notebook.add(imports_frame, text="📦 Imports")
        
        imports_header = tk.Frame(imports_frame, bg="#7B1FA2", height=50)
        imports_header.pack(fill=tk.X)
        imports_header.pack_propagate(False)
        tk.Label(imports_header, text="📦 Import Table Analysis", font=("Arial", 14, "bold"), 
                bg="#7B1FA2", fg="white").pack(side=tk.LEFT, padx=15, pady=10)
        
        imports_content = tk.Frame(imports_frame)
        imports_content.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        imports_tree = ttk.Treeview(imports_content, columns=("dll", "function", "risk"), show="headings")
        imports_tree.heading("dll", text="DLL")
        imports_tree.heading("function", text="Function")
        imports_tree.heading("risk", text="Risk Level")
        imports_tree.column("dll", width=200)
        imports_tree.column("function", width=350)
        imports_tree.column("risk", width=100)
        
        imports_scroll = tk.Scrollbar(imports_content, command=imports_tree.yview)
        imports_tree.configure(yscrollcommand=imports_scroll.set)
        imports_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        imports_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Parse imports if PE file
        imports_tree.tag_configure("high", background="#ffcdd2")
        imports_tree.tag_configure("moderate", background="#fff9c4")
        imports_tree.tag_configure("low", background="#c8e6c9")
        
        suspicious_imports = {
            'high': ['CreateRemoteThread', 'VirtualAllocEx', 'WriteProcessMemory', 'NtUnmapViewOfSection',
                    'SetWindowsHookEx', 'GetAsyncKeyState', 'NtQueueApcThread', 'RtlCreateUserThread'],
            'moderate': ['VirtualAlloc', 'VirtualProtect', 'LoadLibrary', 'GetProcAddress', 'CreateProcess',
                        'ShellExecute', 'WinExec', 'URLDownloadToFile', 'InternetOpen', 'HttpSendRequest',
                        'RegSetValueEx', 'RegCreateKeyEx', 'CreateService', 'OpenProcess']
        }
        
        imports_summary = {'total': 0, 'high': 0, 'moderate': 0}
        
        if len(self.data) > 64 and self.data[0:2] == b'MZ':
            try:
                pe_offset = struct.unpack('<I', self.data[0x3C:0x40])[0]
                if pe_offset < len(self.data) - 4 and self.data[pe_offset:pe_offset+4] == b'PE\x00\x00':
                    # Get optional header info
                    machine = struct.unpack('<H', self.data[pe_offset+4:pe_offset+6])[0]
                    is_64bit = machine == 0x8664
                    
                    opt_offset = pe_offset + 24
                    if is_64bit:
                        import_rva = struct.unpack('<I', self.data[opt_offset+112:opt_offset+116])[0]
                    else:
                        import_rva = struct.unpack('<I', self.data[opt_offset+104:opt_offset+108])[0]
                    
                    # Parse section headers to convert RVA to file offset
                    num_sections = struct.unpack('<H', self.data[pe_offset+6:pe_offset+8])[0]
                    opt_header_size = struct.unpack('<H', self.data[pe_offset+20:pe_offset+22])[0]
                    section_offset = pe_offset + 24 + opt_header_size
                    
                    sections = []
                    for i in range(num_sections):
                        sec_off = section_offset + i * 40
                        virt_size = struct.unpack('<I', self.data[sec_off+8:sec_off+12])[0]
                        virt_addr = struct.unpack('<I', self.data[sec_off+12:sec_off+16])[0]
                        raw_size = struct.unpack('<I', self.data[sec_off+16:sec_off+20])[0]
                        raw_ptr = struct.unpack('<I', self.data[sec_off+20:sec_off+24])[0]
                        sections.append((virt_addr, virt_size, raw_ptr, raw_size))
                    
                    def rva_to_offset(rva):
                        for virt_addr, virt_size, raw_ptr, raw_size in sections:
                            if virt_addr <= rva < virt_addr + max(virt_size, raw_size):
                                return raw_ptr + (rva - virt_addr)
                        return None
                    
                    # Parse import directory
                    if import_rva > 0:
                        import_offset = rva_to_offset(import_rva)
                        if import_offset:
                            idx = 0
                            while True:
                                desc_offset = import_offset + idx * 20
                                if desc_offset + 20 > len(self.data):
                                    break
                                
                                name_rva = struct.unpack('<I', self.data[desc_offset+12:desc_offset+16])[0]
                                if name_rva == 0:
                                    break
                                
                                name_offset = rva_to_offset(name_rva)
                                if name_offset:
                                    dll_name = ""
                                    for j in range(256):
                                        if name_offset + j >= len(self.data):
                                            break
                                        c = self.data[name_offset + j]
                                        if c == 0:
                                            break
                                        dll_name += chr(c)
                                    
                                    # Get import lookup table
                                    ilt_rva = struct.unpack('<I', self.data[desc_offset:desc_offset+4])[0]
                                    if ilt_rva == 0:
                                        ilt_rva = struct.unpack('<I', self.data[desc_offset+16:desc_offset+20])[0]
                                    
                                    if ilt_rva > 0:
                                        ilt_offset = rva_to_offset(ilt_rva)
                                        if ilt_offset:
                                            func_idx = 0
                                            entry_size = 8 if is_64bit else 4
                                            while True:
                                                entry_offset = ilt_offset + func_idx * entry_size
                                                if entry_offset + entry_size > len(self.data):
                                                    break
                                                
                                                if is_64bit:
                                                    entry = struct.unpack('<Q', self.data[entry_offset:entry_offset+8])[0]
                                                    ordinal_flag = 0x8000000000000000
                                                else:
                                                    entry = struct.unpack('<I', self.data[entry_offset:entry_offset+4])[0]
                                                    ordinal_flag = 0x80000000
                                                
                                                if entry == 0:
                                                    break
                                                
                                                func_name = ""
                                                if entry & ordinal_flag:
                                                    func_name = f"Ordinal {entry & 0xFFFF}"
                                                else:
                                                    hint_offset = rva_to_offset(entry & 0x7FFFFFFF)
                                                    if hint_offset and hint_offset + 2 < len(self.data):
                                                        for j in range(256):
                                                            if hint_offset + 2 + j >= len(self.data):
                                                                break
                                                            c = self.data[hint_offset + 2 + j]
                                                            if c == 0:
                                                                break
                                                            func_name += chr(c)
                                                
                                                if func_name:
                                                    risk = "Low"
                                                    tag = "low"
                                                    for hi in suspicious_imports['high']:
                                                        if hi.lower() in func_name.lower():
                                                            risk = "⚠ High"
                                                            tag = "high"
                                                            imports_summary['high'] += 1
                                                            break
                                                    if risk == "Low":
                                                        for mi in suspicious_imports['moderate']:
                                                            if mi.lower() in func_name.lower():
                                                                risk = "⚡ Moderate"
                                                                tag = "moderate"
                                                                imports_summary['moderate'] += 1
                                                                break
                                                    
                                                    imports_tree.insert("", tk.END, values=(dll_name, func_name, risk), tags=(tag,))
                                                    imports_summary['total'] += 1
                                                
                                                func_idx += 1
                                                if func_idx > 1000:
                                                    break
                                
                                idx += 1
                                if idx > 100:
                                    break
            except Exception as e:
                imports_tree.insert("", tk.END, values=("Error parsing imports", str(e), ""))
        else:
            imports_tree.insert("", tk.END, values=("Not a PE file", "Import analysis requires PE format", ""))
        
        # Import summary
        import_summary_frame = tk.Frame(imports_frame, bg="#f3e5f5", relief=tk.RAISED, borderwidth=1)
        import_summary_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(import_summary_frame, text=f"Total Imports: {imports_summary['total']} | High Risk: {imports_summary['high']} | Moderate Risk: {imports_summary['moderate']}", 
                font=("Arial", 10, "bold"), bg="#f3e5f5").pack(pady=5)
        
        # ===== TAB 4: Section Analysis =====
        sections_frame = ttk.Frame(notebook)
        notebook.add(sections_frame, text="📊 Sections")
        
        sections_header = tk.Frame(sections_frame, bg="#F57C00", height=50)
        sections_header.pack(fill=tk.X)
        sections_header.pack_propagate(False)
        tk.Label(sections_header, text="📊 Section Analysis & Permissions", font=("Arial", 14, "bold"), 
                bg="#F57C00", fg="white").pack(side=tk.LEFT, padx=15, pady=10)
        
        # Info label
        sections_info = tk.Label(sections_frame, text="💡 Double-click a section to jump to its location in the hex view", 
                                font=("Arial", 9), bg="#fff3e0", fg="#e65100")
        sections_info.pack(fill=tk.X, padx=10, pady=2)
        
        sections_content = tk.Frame(sections_frame)
        sections_content.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        sections_tree = ttk.Treeview(sections_content, columns=("name", "vaddr", "rawptr", "vsize", "rsize", "entropy", "perms", "flags"), show="headings")
        sections_tree.heading("name", text="Name")
        sections_tree.heading("vaddr", text="Virtual Addr")
        sections_tree.heading("rawptr", text="File Offset")
        sections_tree.heading("vsize", text="Virtual Size")
        sections_tree.heading("rsize", text="Raw Size")
        sections_tree.heading("entropy", text="Entropy")
        sections_tree.heading("perms", text="Permissions")
        sections_tree.heading("flags", text="Flags")
        sections_tree.column("name", width=80)
        sections_tree.column("vaddr", width=100)
        sections_tree.column("rawptr", width=100)
        sections_tree.column("vsize", width=80)
        sections_tree.column("rsize", width=80)
        sections_tree.column("entropy", width=60)
        sections_tree.column("perms", width=80)
        sections_tree.column("flags", width=120)
        
        sections_scroll = tk.Scrollbar(sections_content, command=sections_tree.yview)
        sections_tree.configure(yscrollcommand=sections_scroll.set)
        sections_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sections_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        
        sections_tree.tag_configure("dangerous", background="#ffcdd2")
        sections_tree.tag_configure("suspicious", background="#fff9c4")
        sections_tree.tag_configure("packed", background="#e1bee7")
        
        suspicious_sections = []
        
        if len(self.data) > 64 and self.data[0:2] == b'MZ':
            try:
                pe_offset = struct.unpack('<I', self.data[0x3C:0x40])[0]
                if pe_offset < len(self.data) - 4 and self.data[pe_offset:pe_offset+4] == b'PE\x00\x00':
                    num_sections = struct.unpack('<H', self.data[pe_offset+6:pe_offset+8])[0]
                    opt_header_size = struct.unpack('<H', self.data[pe_offset+20:pe_offset+22])[0]
                    section_offset = pe_offset + 24 + opt_header_size
                    
                    for i in range(num_sections):
                        sec_off = section_offset + i * 40
                        name = self.data[sec_off:sec_off+8].rstrip(b'\x00').decode('ascii', errors='ignore')
                        virt_size = struct.unpack('<I', self.data[sec_off+8:sec_off+12])[0]
                        virt_addr = struct.unpack('<I', self.data[sec_off+12:sec_off+16])[0]
                        raw_size = struct.unpack('<I', self.data[sec_off+16:sec_off+20])[0]
                        raw_ptr = struct.unpack('<I', self.data[sec_off+20:sec_off+24])[0]
                        characteristics = struct.unpack('<I', self.data[sec_off+36:sec_off+40])[0]
                        
                        # Calculate entropy
                        entropy = 0.0
                        if raw_size > 0 and raw_ptr + raw_size <= len(self.data):
                            section_data = self.data[raw_ptr:raw_ptr+raw_size]
                            if len(section_data) > 0:
                                freq = [0] * 256
                                for byte in section_data:
                                    freq[byte] += 1
                                for f in freq:
                                    if f > 0:
                                        p = f / len(section_data)
                                        entropy -= p * math.log2(p)
                        
                        # Parse permissions
                        perms = []
                        if characteristics & 0x20000000: perms.append("X")  # Executable
                        if characteristics & 0x40000000: perms.append("R")  # Readable
                        if characteristics & 0x80000000: perms.append("W")  # Writable
                        perm_str = "".join(perms) if perms else "---"
                        
                        # Parse flags
                        flags = []
                        if characteristics & 0x00000020: flags.append("CODE")
                        if characteristics & 0x00000040: flags.append("IDATA")
                        if characteristics & 0x00000080: flags.append("UDATA")
                        if characteristics & 0x02000000: flags.append("DISCARD")
                        if characteristics & 0x04000000: flags.append("NOCACHE")
                        if characteristics & 0x08000000: flags.append("NOPAGE")
                        if characteristics & 0x10000000: flags.append("SHARED")
                        flag_str = ", ".join(flags) if flags else "-"
                        
                        # Determine tag
                        tag = ""
                        warning = ""
                        if "W" in perm_str and "X" in perm_str:
                            tag = "dangerous"
                            warning = "⚠ W+X: Self-modifying code possible"
                            suspicious_sections.append((name, warning))
                        elif entropy > 7.0:
                            tag = "packed"
                            warning = "⚠ High entropy: Possibly packed/encrypted"
                            suspicious_sections.append((name, warning))
                        elif name.lower() not in ['.text', '.data', '.rdata', '.bss', '.rsrc', '.reloc', '.idata', '.edata']:
                            tag = "suspicious"
                            warning = "⚠ Unusual section name"
                            suspicious_sections.append((name, warning))
                        
                        sections_tree.insert("", tk.END, 
                                           values=(name, f"0x{virt_addr:08X}", f"0x{raw_ptr:08X}",
                                                  f"0x{virt_size:X}", f"0x{raw_size:X}", f"{entropy:.2f}", perm_str, flag_str), 
                                           tags=(tag,))
            except Exception as e:
                sections_tree.insert("", tk.END, values=("Error", str(e), "", "", "", "", "", ""))
        else:
            sections_tree.insert("", tk.END, values=("Not a PE file", "", "", "", "", "", "", ""))
        
        # Double-click to jump to section
        def on_section_double_click(event):
            selection = sections_tree.selection()
            if selection:
                item = sections_tree.item(selection[0])
                raw_ptr_str = item['values'][2]  # File Offset column
                if raw_ptr_str and raw_ptr_str.startswith("0x"):
                    offset = int(raw_ptr_str, 16)
                    raw_size_str = item['values'][4]  # Raw Size column
                    length = 16  # Default highlight length
                    if raw_size_str and raw_size_str.startswith("0x"):
                        length = min(int(raw_size_str, 16), 64)  # Highlight first 64 bytes max
                    if not keep_open_var.get():
                        analysis_win.destroy()
                    self.highlight_offset(offset, length)
        
        sections_tree.bind("<Double-Button-1>", on_section_double_click)
        
        # Section warnings
        if suspicious_sections:
            warn_frame = tk.Frame(sections_frame, bg="#ffebee", relief=tk.RAISED, borderwidth=1)
            warn_frame.pack(fill=tk.X, padx=10, pady=5)
            tk.Label(warn_frame, text="⚠ Section Warnings:", font=("Arial", 10, "bold"), bg="#ffebee", fg="#c62828").pack(anchor='w', padx=10, pady=5)
            for sec_name, warning in suspicious_sections:
                tk.Label(warn_frame, text=f"  • {sec_name}: {warning}", font=("Arial", 9), bg="#ffebee", fg="#c62828").pack(anchor='w', padx=20)
        
        # ===== TAB 5: Packer Detection =====
        packer_frame = ttk.Frame(notebook)
        notebook.add(packer_frame, text="📦 Packer Detection")
        
        packer_header = tk.Frame(packer_frame, bg="#C62828", height=50)
        packer_header.pack(fill=tk.X)
        packer_header.pack_propagate(False)
        tk.Label(packer_header, text="📦 Packer/Protector Detection", font=("Arial", 14, "bold"), 
                bg="#C62828", fg="white").pack(side=tk.LEFT, padx=15, pady=10)
        
        packer_content = tk.Frame(packer_frame, bg="#fafafa")
        packer_content.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Packer signatures
        packer_sigs = [
            ("UPX", [b'UPX0', b'UPX1', b'UPX2', b'UPX!']),
            ("ASPack", [b'.aspack', b'.adata', b'ASPack']),
            ("PECompact", [b'PEC2', b'.pec', b'PECompact']),
            ("Themida/WinLicense", [b'.themida', b'Themida', b'WinLicense']),
            ("VMProtect", [b'.vmp0', b'.vmp1', b'.vmp2', b'VMProtect']),
            ("Armadillo", [b'.data1', b'PDATA', b'Armadillo']),
            ("Enigma", [b'.enigma', b'Enigma protector']),
            ("PEtite", [b'.petite', b'PEtite']),
            ("MPRESS", [b'.MPRESS1', b'.MPRESS2']),
            ("NSPack", [b'.nsp0', b'.nsp1', b'nsPack']),
            ("MEW", [b'MEW', b'.mew']),
            ("FSG", [b'FSG!']),
            ("Obsidium", [b'.obsidiu']),
            ("ExeCryptor", [b'.execry']),
            ("Yoda's Crypter", [b"Yoda's Crypter", b'yC', b'.yP']),
            (".NET Obfuscator", [b'ConfuserEx', b'Dotfuscator', b'SmartAssembly', b'Eazfuscator']),
            ("Babel", [b'Babel']),
            ("PyInstaller", [b'PYZ00_PYZ-', b'MEIPASS', b'_MEIPASS2']),
            ("AutoIt", [b'AU3!', b'AutoIt']),
            ("NSIS", [b'Nullsoft', b'NSIS', b'\xef\xbe\xad\xdeNullsoft']),
            ("Inno Setup", [b'Inno Setup', b'InnoSetup']),
            ("InstallShield", [b'InstallShield']),
        ]
        
        detected_packers = []
        
        for packer_name, signatures in packer_sigs:
            for sig in signatures:
                if sig in self.data:
                    detected_packers.append((packer_name, sig.decode('ascii', errors='ignore')))
                    break
        
        # High entropy check
        if len(self.data) > 0:
            freq = [0] * 256
            for byte in self.data:
                freq[byte] += 1
            total_entropy = 0
            for f in freq:
                if f > 0:
                    p = f / len(self.data)
                    total_entropy -= p * math.log2(p)
            
            if total_entropy > 7.5:
                detected_packers.append(("Unknown Packer/Crypter", f"High overall entropy: {total_entropy:.2f}"))
        
        if detected_packers:
            warn_label = tk.Label(packer_content, text="⚠ PACKER/PROTECTOR DETECTED", 
                                 font=("Arial", 16, "bold"), bg="#ffcdd2", fg="#c62828")
            warn_label.pack(fill=tk.X, pady=20)
            
            for packer, sig in detected_packers:
                pack_frame = tk.Frame(packer_content, bg="#ffebee", relief=tk.RAISED, borderwidth=1)
                pack_frame.pack(fill=tk.X, pady=5, padx=20)
                tk.Label(pack_frame, text=f"📦 {packer}", font=("Arial", 12, "bold"), bg="#ffebee", fg="#c62828").pack(side=tk.LEFT, padx=15, pady=10)
                tk.Label(pack_frame, text=f"Signature: {sig}", font=("Arial", 10), bg="#ffebee", fg="#666").pack(side=tk.LEFT, padx=10, pady=10)
            
            tk.Label(packer_content, text="\n⚠ Warning: Packed/protected files often indicate:\n" +
                    "  • Attempt to hide malicious code\n" +
                    "  • Evasion of antivirus detection\n" +
                    "  • Protection of intellectual property (legitimate use)\n\n" +
                    "Consider unpacking before further analysis.",
                    font=("Arial", 10), bg="#fafafa", justify=tk.LEFT).pack(anchor='w', padx=20, pady=10)
        else:
            ok_label = tk.Label(packer_content, text="✅ No Known Packers Detected", 
                               font=("Arial", 16, "bold"), bg="#c8e6c9", fg="#2e7d32")
            ok_label.pack(fill=tk.X, pady=20)
            
            tk.Label(packer_content, text="This file does not appear to be packed with common packers.\n" +
                    f"Overall file entropy: {total_entropy:.2f}/8.0",
                    font=("Arial", 10), bg="#fafafa").pack(pady=10)
        
        # ===== TAB 6: Hex Pattern Search =====
        pattern_frame = ttk.Frame(notebook)
        notebook.add(pattern_frame, text="🔎 Pattern Search")
        
        pattern_header = tk.Frame(pattern_frame, bg="#455A64", height=50)
        pattern_header.pack(fill=tk.X)
        pattern_header.pack_propagate(False)
        tk.Label(pattern_header, text="🔎 Hex Pattern Search", font=("Arial", 14, "bold"), 
                bg="#455A64", fg="white").pack(side=tk.LEFT, padx=15, pady=10)
        
        pattern_ctrl = tk.Frame(pattern_frame, bg="#eceff1")
        pattern_ctrl.pack(fill=tk.X, padx=10, pady=10)
        
        tk.Label(pattern_ctrl, text="Hex Pattern (e.g., 4D5A or 4D ?? 5A):", bg="#eceff1").pack(side=tk.LEFT, padx=5)
        pattern_entry = tk.Entry(pattern_ctrl, width=40, font=("Courier", 10))
        pattern_entry.pack(side=tk.LEFT, padx=5)
        
        pattern_results = scrolledtext.ScrolledText(pattern_frame, font=("Courier", 10), height=20)
        pattern_results.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        
        def search_pattern():
            pattern_results.delete(1.0, tk.END)
            pattern_str = pattern_entry.get().strip().upper().replace(" ", "")
            
            if not pattern_str:
                pattern_results.insert(tk.END, "Please enter a hex pattern.")
                return
            
            # Convert pattern with wildcards
            pattern_bytes = []
            i = 0
            while i < len(pattern_str):
                if pattern_str[i:i+2] == '??':
                    pattern_bytes.append(None)  # Wildcard
                    i += 2
                else:
                    try:
                        pattern_bytes.append(int(pattern_str[i:i+2], 16))
                        i += 2
                    except ValueError:
                        pattern_results.insert(tk.END, f"Invalid hex pattern at position {i}")
                        return
            
            if not pattern_bytes:
                pattern_results.insert(tk.END, "Invalid pattern.")
                return
            
            # Search for pattern
            matches = []
            for offset in range(len(self.data) - len(pattern_bytes) + 1):
                match = True
                for j, pb in enumerate(pattern_bytes):
                    if pb is not None and self.data[offset + j] != pb:
                        match = False
                        break
                if match:
                    matches.append(offset)
                    if len(matches) >= 1000:
                        break
            
            if matches:
                pattern_results.insert(tk.END, f"Found {len(matches)} matches:\n\n")
                for offset in matches[:100]:
                    context_start = max(0, offset - 8)
                    context_end = min(len(self.data), offset + len(pattern_bytes) + 8)
                    context = self.data[context_start:context_end].hex().upper()
                    pattern_results.insert(tk.END, f"0x{offset:08X}: {context}\n")
                if len(matches) > 100:
                    pattern_results.insert(tk.END, f"\n... and {len(matches) - 100} more matches")
            else:
                pattern_results.insert(tk.END, "No matches found.")
        
        tk.Button(pattern_ctrl, text="🔍 Search", command=search_pattern, bg="#607D8B", fg="white").pack(side=tk.LEFT, padx=10)
        
        # Common shellcode patterns
        common_frame = tk.Frame(pattern_frame, bg="#eceff1")
        common_frame.pack(fill=tk.X, padx=10, pady=5)
        tk.Label(common_frame, text="Common patterns:", bg="#eceff1", font=("Arial", 9, "bold")).pack(side=tk.LEFT, padx=5)
        
        common_patterns = [
            ("MZ Header", "4D5A"),
            ("PE Signature", "50450000"),
            ("NOP Sled", "9090909090"),
            ("INT 3", "CCCCCCCC"),
            ("JMP Short", "EB??"),
            ("CALL", "E8????????"),
        ]
        
        for name, pattern in common_patterns:
            btn = tk.Button(common_frame, text=name, font=("Arial", 8),
                           command=lambda p=pattern: [pattern_entry.delete(0, tk.END), pattern_entry.insert(0, p), search_pattern()])
            btn.pack(side=tk.LEFT, padx=2)
        
        # Bottom frame with checkbox and close button
        bottom_frame = tk.Frame(analysis_win)
        bottom_frame.pack(pady=10)
        
        tk.Checkbutton(bottom_frame, text="Keep window open when navigating", variable=keep_open_var,
                      font=("Arial", 9)).pack(side=tk.LEFT, padx=20)
        tk.Button(bottom_frame, text="Close", command=analysis_win.destroy, padx=30, pady=5).pack(side=tk.LEFT, padx=10)
    
    def copy_to_clipboard(self, text):
        """Copy text to clipboard"""
        self.root.clipboard_clear()
        self.root.clipboard_append(text)
        self.update_status(f"Copied to clipboard")

    def toggle_assembler(self):
        """Toggle assembler visibility"""
        # This would need more complex handling to truly hide/show
        # For now just a placeholder
        pass
    
    def update_disassembly_view(self):
        """Update the assembly input with disassembled code from current view position"""
        if not self.data:
            return
        
        try:
            # Get the first visible line
            first_visible = self.text_widget.index("@0,0")
            line_num = int(first_visible.split('.')[0])
            
            # Calculate byte offset from line number (16 bytes per line)
            offset = (line_num - 1) * 16
            self.current_view_offset = offset
            
            # Get bytes to disassemble (enough for several instructions)
            num_bytes = 64  # Disassemble ~64 bytes worth
            if offset >= len(self.data):
                return
            
            end_offset = min(offset + num_bytes, len(self.data))
            bytes_to_disasm = self.data[offset:end_offset]
            
            if not bytes_to_disasm:
                return
            
            # Get architecture and base address
            arch = self.asm_arch_var.get()
            try:
                base_str = self.asm_base_var.get()
                if base_str.lower().startswith("0x"):
                    base_addr = int(base_str, 16)
                else:
                    base_addr = int(base_str)
            except:
                base_addr = 0x00400000
            
            # Disassemble
            asm_lines = []
            output_lines = []
            current_addr = base_addr + offset
            i = 0
            
            while i < len(bytes_to_disasm) and len(asm_lines) < 12:  # Limit to ~12 instructions
                result = self.disassemble_instruction(bytes_to_disasm, i, arch, current_addr)
                if result['success']:
                    bytes_used = result['bytes_used']
                    bytes_hex = ' '.join(f'{bytes_to_disasm[i+j]:02X}' for j in range(bytes_used))
                    asm_lines.append(result['instruction'])
                    output_lines.append(f"{current_addr:08X}  {bytes_hex:<24}  {result['instruction']}")
                    current_addr += bytes_used
                    i += bytes_used
                else:
                    # Unknown byte
                    asm_lines.append(f"db 0x{bytes_to_disasm[i]:02X}")
                    output_lines.append(f"{current_addr:08X}  {bytes_to_disasm[i]:02X}                        db 0x{bytes_to_disasm[i]:02X}")
                    current_addr += 1
                    i += 1
            
            # Update input area
            self.asm_input.delete('1.0', tk.END)
            self.asm_input.insert('1.0', f"; Disassembly at offset 0x{offset:08X}\n")
            self.asm_input.insert(tk.END, '\n'.join(asm_lines))
            
            # Update output area
            self.asm_output.config(state=tk.NORMAL)
            self.asm_output.delete('1.0', tk.END)
            self.asm_output.insert(tk.END, '\n'.join(output_lines))
            self.asm_output.config(state=tk.DISABLED)
            
        except Exception as e:
            pass  # Silently ignore errors during auto-disassembly
    
    def disassemble_instruction(self, data, offset, arch, addr):
        """Disassemble a single instruction from byte data"""
        if offset >= len(data):
            return {'success': False, 'error': 'End of data'}
        
        b = data[offset]
        is_64bit = arch == "x64"
        
        # NOP
        if b == 0x90:
            return {'success': True, 'instruction': 'nop', 'bytes_used': 1}
        
        # INT3
        if b == 0xCC:
            return {'success': True, 'instruction': 'int3', 'bytes_used': 1}
        
        # RET
        if b == 0xC3:
            return {'success': True, 'instruction': 'ret', 'bytes_used': 1}
        
        # RET imm16
        if b == 0xC2 and offset + 2 < len(data):
            imm = data[offset+1] | (data[offset+2] << 8)
            return {'success': True, 'instruction': f'ret 0x{imm:X}', 'bytes_used': 3}
        
        # PUSH reg32 (50-57)
        if 0x50 <= b <= 0x57:
            regs = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']
            if is_64bit:
                regs = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi']
            return {'success': True, 'instruction': f'push {regs[b - 0x50]}', 'bytes_used': 1}
        
        # POP reg32 (58-5F)
        if 0x58 <= b <= 0x5F:
            regs = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']
            if is_64bit:
                regs = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi']
            return {'success': True, 'instruction': f'pop {regs[b - 0x58]}', 'bytes_used': 1}
        
        # PUSH imm8
        if b == 0x6A and offset + 1 < len(data):
            imm = data[offset+1]
            return {'success': True, 'instruction': f'push 0x{imm:02X}', 'bytes_used': 2}
        
        # PUSH imm32
        if b == 0x68 and offset + 4 < len(data):
            imm = data[offset+1] | (data[offset+2] << 8) | (data[offset+3] << 16) | (data[offset+4] << 24)
            return {'success': True, 'instruction': f'push 0x{imm:08X}', 'bytes_used': 5}
        
        # MOV reg32, imm32 (B8-BF)
        if 0xB8 <= b <= 0xBF and offset + 4 < len(data):
            regs = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']
            imm = data[offset+1] | (data[offset+2] << 8) | (data[offset+3] << 16) | (data[offset+4] << 24)
            return {'success': True, 'instruction': f'mov {regs[b - 0xB8]}, 0x{imm:08X}', 'bytes_used': 5}
        
        # INC reg32 (40-47) - x86 only
        if 0x40 <= b <= 0x47 and not is_64bit:
            regs = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']
            return {'success': True, 'instruction': f'inc {regs[b - 0x40]}', 'bytes_used': 1}
        
        # DEC reg32 (48-4F) - x86 only
        if 0x48 <= b <= 0x4F and not is_64bit:
            regs = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']
            return {'success': True, 'instruction': f'dec {regs[b - 0x48]}', 'bytes_used': 1}
        
        # REX prefixes (40-4F) - x64 only
        if 0x40 <= b <= 0x4F and is_64bit and offset + 1 < len(data):
            rex = b
            next_b = data[offset + 1]
            if rex == 0x48:  # REX.W
                # MOV reg64, reg64 (89 /r)
                if next_b == 0x89 and offset + 2 < len(data):
                    modrm = data[offset + 2]
                    if (modrm & 0xC0) == 0xC0:
                        regs = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi']
                        src = (modrm >> 3) & 7
                        dst = modrm & 7
                        return {'success': True, 'instruction': f'mov {regs[dst]}, {regs[src]}', 'bytes_used': 3}
                # XOR reg64, reg64 (31 /r)
                if next_b == 0x31 and offset + 2 < len(data):
                    modrm = data[offset + 2]
                    if (modrm & 0xC0) == 0xC0:
                        regs = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi']
                        src = (modrm >> 3) & 7
                        dst = modrm & 7
                        return {'success': True, 'instruction': f'xor {regs[dst]}, {regs[src]}', 'bytes_used': 3}
                # ADD reg64, reg64 (01 /r)
                if next_b == 0x01 and offset + 2 < len(data):
                    modrm = data[offset + 2]
                    if (modrm & 0xC0) == 0xC0:
                        regs = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi']
                        src = (modrm >> 3) & 7
                        dst = modrm & 7
                        return {'success': True, 'instruction': f'add {regs[dst]}, {regs[src]}', 'bytes_used': 3}
                # SUB reg64, reg64 (29 /r)
                if next_b == 0x29 and offset + 2 < len(data):
                    modrm = data[offset + 2]
                    if (modrm & 0xC0) == 0xC0:
                        regs = ['rax', 'rcx', 'rdx', 'rbx', 'rsp', 'rbp', 'rsi', 'rdi']
                        src = (modrm >> 3) & 7
                        dst = modrm & 7
                        return {'success': True, 'instruction': f'sub {regs[dst]}, {regs[src]}', 'bytes_used': 3}
        
        # MOV reg32, reg32 (89 /r)
        if b == 0x89 and offset + 1 < len(data):
            modrm = data[offset + 1]
            if (modrm & 0xC0) == 0xC0:
                regs = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']
                src = (modrm >> 3) & 7
                dst = modrm & 7
                return {'success': True, 'instruction': f'mov {regs[dst]}, {regs[src]}', 'bytes_used': 2}
        
        # XOR reg32, reg32 (31 /r)
        if b == 0x31 and offset + 1 < len(data):
            modrm = data[offset + 1]
            if (modrm & 0xC0) == 0xC0:
                regs = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']
                src = (modrm >> 3) & 7
                dst = modrm & 7
                return {'success': True, 'instruction': f'xor {regs[dst]}, {regs[src]}', 'bytes_used': 2}
        
        # ADD reg32, reg32 (01 /r)
        if b == 0x01 and offset + 1 < len(data):
            modrm = data[offset + 1]
            if (modrm & 0xC0) == 0xC0:
                regs = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']
                src = (modrm >> 3) & 7
                dst = modrm & 7
                return {'success': True, 'instruction': f'add {regs[dst]}, {regs[src]}', 'bytes_used': 2}
        
        # SUB reg32, reg32 (29 /r)
        if b == 0x29 and offset + 1 < len(data):
            modrm = data[offset + 1]
            if (modrm & 0xC0) == 0xC0:
                regs = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']
                src = (modrm >> 3) & 7
                dst = modrm & 7
                return {'success': True, 'instruction': f'sub {regs[dst]}, {regs[src]}', 'bytes_used': 2}
        
        # CMP reg32, reg32 (39 /r)
        if b == 0x39 and offset + 1 < len(data):
            modrm = data[offset + 1]
            if (modrm & 0xC0) == 0xC0:
                regs = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']
                src = (modrm >> 3) & 7
                dst = modrm & 7
                return {'success': True, 'instruction': f'cmp {regs[dst]}, {regs[src]}', 'bytes_used': 2}
        
        # TEST reg32, reg32 (85 /r)
        if b == 0x85 and offset + 1 < len(data):
            modrm = data[offset + 1]
            if (modrm & 0xC0) == 0xC0:
                regs = ['eax', 'ecx', 'edx', 'ebx', 'esp', 'ebp', 'esi', 'edi']
                src = (modrm >> 3) & 7
                dst = modrm & 7
                return {'success': True, 'instruction': f'test {regs[dst]}, {regs[src]}', 'bytes_used': 2}
        
        # JMP rel8
        if b == 0xEB and offset + 1 < len(data):
            rel = data[offset + 1]
            if rel > 127:
                rel = rel - 256
            target = addr + 2 + rel
            return {'success': True, 'instruction': f'jmp 0x{target:08X}', 'bytes_used': 2}
        
        # JMP rel32
        if b == 0xE9 and offset + 4 < len(data):
            rel = data[offset+1] | (data[offset+2] << 8) | (data[offset+3] << 16) | (data[offset+4] << 24)
            if rel > 0x7FFFFFFF:
                rel = rel - 0x100000000
            target = addr + 5 + rel
            return {'success': True, 'instruction': f'jmp 0x{target:08X}', 'bytes_used': 5}
        
        # CALL rel32
        if b == 0xE8 and offset + 4 < len(data):
            rel = data[offset+1] | (data[offset+2] << 8) | (data[offset+3] << 16) | (data[offset+4] << 24)
            if rel > 0x7FFFFFFF:
                rel = rel - 0x100000000
            target = addr + 5 + rel
            return {'success': True, 'instruction': f'call 0x{target:08X}', 'bytes_used': 5}
        
        # Conditional jumps (short)
        jcc_map = {0x74: 'je', 0x75: 'jne', 0x7C: 'jl', 0x7D: 'jge', 0x7E: 'jle', 0x7F: 'jg',
                   0x77: 'ja', 0x73: 'jae', 0x72: 'jb', 0x76: 'jbe', 0x78: 'js', 0x79: 'jns',
                   0x70: 'jo', 0x71: 'jno'}
        if b in jcc_map and offset + 1 < len(data):
            rel = data[offset + 1]
            if rel > 127:
                rel = rel - 256
            target = addr + 2 + rel
            return {'success': True, 'instruction': f'{jcc_map[b]} 0x{target:08X}', 'bytes_used': 2}
        
        # INT n
        if b == 0xCD and offset + 1 < len(data):
            return {'success': True, 'instruction': f'int 0x{data[offset+1]:02X}', 'bytes_used': 2}
        
        # Single-byte instructions
        single_byte = {
            0xF4: 'hlt', 0xF8: 'clc', 0xF9: 'stc', 0xFA: 'cli', 0xFB: 'sti',
            0xFC: 'cld', 0xFD: 'std', 0xC9: 'leave', 0x9C: 'pushfd', 0x9D: 'popfd',
            0x60: 'pushad', 0x61: 'popad', 0x99: 'cdq', 0x98: 'cwde'
        }
        if b in single_byte:
            return {'success': True, 'instruction': single_byte[b], 'bytes_used': 1}
        
        # Two-byte opcodes (0F xx)
        if b == 0x0F and offset + 1 < len(data):
            b2 = data[offset + 1]
            if b2 == 0x05:
                return {'success': True, 'instruction': 'syscall', 'bytes_used': 2}
            if b2 == 0x34:
                return {'success': True, 'instruction': 'sysenter', 'bytes_used': 2}
            if b2 == 0xA2:
                return {'success': True, 'instruction': 'cpuid', 'bytes_used': 2}
            if b2 == 0x31:
                return {'success': True, 'instruction': 'rdtsc', 'bytes_used': 2}
            if b2 == 0x1F and offset + 2 < len(data):
                # Multi-byte NOP
                modrm = data[offset + 2]
                if modrm == 0x00:
                    return {'success': True, 'instruction': 'nop dword ptr [eax]', 'bytes_used': 3}
                if modrm == 0x44 and offset + 3 < len(data):
                    return {'success': True, 'instruction': 'nop dword ptr [eax+0]', 'bytes_used': 4}
        
        # Unknown instruction - show as db
        return {'success': False, 'error': 'Unknown opcode'}
    
    def assemble_code(self):
        """Assemble the code in the input field"""
        try:
            asm_code = self.asm_input.get(1.0, tk.END).strip()
            arch = self.asm_arch_var.get()
            base_addr_str = self.asm_base_var.get()
            
            try:
                base_addr = int(base_addr_str, 16) if base_addr_str.startswith("0x") else int(base_addr_str)
            except ValueError:
                base_addr = 0x00400000
            
            # Simple built-in assembler for common x86/x64 instructions
            self.assembled_bytes = bytearray()
            output_lines = []
            current_addr = base_addr
            
            lines = asm_code.split('\n')
            for line in lines:
                line = line.strip()
                # Remove comments
                if ';' in line:
                    line = line[:line.index(';')].strip()
                if not line:
                    continue
                
                # Try to assemble the instruction
                result = self.assemble_instruction(line, arch, current_addr)
                if result['success']:
                    bytes_hex = ' '.join(f'{b:02X}' for b in result['bytes'])
                    output_lines.append(f"{current_addr:08X}  {bytes_hex:<24}  {line}")
                    self.assembled_bytes.extend(result['bytes'])
                    current_addr += len(result['bytes'])
                else:
                    output_lines.append(f"{current_addr:08X}  {'ERROR':<24}  {line} ; {result['error']}")
            
            # Update output
            self.asm_output.config(state=tk.NORMAL)
            self.asm_output.delete(1.0, tk.END)
            for line in output_lines:
                self.asm_output.insert(tk.END, line + '\n')
            
            # Add summary
            self.asm_output.insert(tk.END, f"\n; Total: {len(self.assembled_bytes)} bytes\n")
            self.asm_output.insert(tk.END, f"; Bytes: {self.assembled_bytes.hex().upper()}\n")
            self.asm_output.config(state=tk.DISABLED)
            
            self.update_status(f"Assembled {len(self.assembled_bytes)} bytes")
        except Exception as e:
            messagebox.showerror("Assembler Error", f"Error during assembly: {str(e)}")
            import traceback
            traceback.print_exc()
    
    def assemble_instruction(self, instruction, arch, addr):
        """Assemble a single instruction - built-in simple assembler"""
        instruction = instruction.lower().strip()
        parts = instruction.replace(',', ' ').split()
        
        if not parts:
            return {'success': False, 'error': 'Empty instruction', 'bytes': []}
        
        mnemonic = parts[0]
        operands = parts[1:] if len(parts) > 1 else []
        
        # Clean operands
        operands = [op.strip() for op in operands if op.strip()]
        
        is_64bit = arch == "x64"
        
        # Register encoding tables
        reg32 = {'eax': 0, 'ecx': 1, 'edx': 2, 'ebx': 3, 'esp': 4, 'ebp': 5, 'esi': 6, 'edi': 7}
        reg64 = {'rax': 0, 'rcx': 1, 'rdx': 2, 'rbx': 3, 'rsp': 4, 'rbp': 5, 'rsi': 6, 'rdi': 7,
                 'r8': 8, 'r9': 9, 'r10': 10, 'r11': 11, 'r12': 12, 'r13': 13, 'r14': 14, 'r15': 15}
        reg8 = {'al': 0, 'cl': 1, 'dl': 2, 'bl': 3, 'ah': 4, 'ch': 5, 'dh': 6, 'bh': 7}
        reg16 = {'ax': 0, 'cx': 1, 'dx': 2, 'bx': 3, 'sp': 4, 'bp': 5, 'si': 6, 'di': 7}
        
        try:
            # NOP
            if mnemonic == 'nop':
                return {'success': True, 'bytes': [0x90], 'error': None}
            
            # INT 3 (breakpoint)
            if mnemonic == 'int3' or (mnemonic == 'int' and operands and operands[0] == '3'):
                return {'success': True, 'bytes': [0xCC], 'error': None}
            
            # INT n
            if mnemonic == 'int' and operands:
                n = self.parse_number(operands[0])
                return {'success': True, 'bytes': [0xCD, n & 0xFF], 'error': None}
            
            # RET
            if mnemonic in ['ret', 'retn']:
                if operands:
                    imm = self.parse_number(operands[0])
                    return {'success': True, 'bytes': [0xC2, imm & 0xFF, (imm >> 8) & 0xFF], 'error': None}
                return {'success': True, 'bytes': [0xC3], 'error': None}
            
            # PUSH reg32/reg64
            if mnemonic == 'push':
                if operands[0] in reg32:
                    return {'success': True, 'bytes': [0x50 + reg32[operands[0]]], 'error': None}
                if is_64bit and operands[0] in reg64:
                    r = reg64[operands[0]]
                    if r < 8:
                        return {'success': True, 'bytes': [0x50 + r], 'error': None}
                    else:
                        return {'success': True, 'bytes': [0x41, 0x50 + (r - 8)], 'error': None}
                # PUSH imm8
                try:
                    imm = self.parse_number(operands[0])
                    if -128 <= imm <= 127:
                        return {'success': True, 'bytes': [0x6A, imm & 0xFF], 'error': None}
                    else:
                        return {'success': True, 'bytes': [0x68] + list(struct.pack('<I', imm & 0xFFFFFFFF)), 'error': None}
                except:
                    pass
            
            # POP reg32/reg64
            if mnemonic == 'pop':
                if operands[0] in reg32:
                    return {'success': True, 'bytes': [0x58 + reg32[operands[0]]], 'error': None}
                if is_64bit and operands[0] in reg64:
                    r = reg64[operands[0]]
                    if r < 8:
                        return {'success': True, 'bytes': [0x58 + r], 'error': None}
                    else:
                        return {'success': True, 'bytes': [0x41, 0x58 + (r - 8)], 'error': None}
            
            # MOV reg, reg / MOV reg, imm
            if mnemonic == 'mov' and len(operands) >= 2:
                dst, src = operands[0], operands[1]
                
                # MOV reg32, reg32
                if dst in reg32 and src in reg32:
                    modrm = 0xC0 | (reg32[src] << 3) | reg32[dst]
                    return {'success': True, 'bytes': [0x89, modrm], 'error': None}
                
                # MOV reg32, imm32
                if dst in reg32:
                    try:
                        imm = self.parse_number(src)
                        return {'success': True, 'bytes': [0xB8 + reg32[dst]] + list(struct.pack('<I', imm & 0xFFFFFFFF)), 'error': None}
                    except:
                        pass
                
                # MOV reg64, reg64 (with REX prefix)
                if is_64bit and dst in reg64 and src in reg64:
                    d, s = reg64[dst], reg64[src]
                    rex = 0x48 | ((s >> 3) << 2) | (d >> 3)
                    modrm = 0xC0 | ((s & 7) << 3) | (d & 7)
                    return {'success': True, 'bytes': [rex, 0x89, modrm], 'error': None}
            
            # XOR reg, reg
            if mnemonic == 'xor' and len(operands) >= 2:
                dst, src = operands[0], operands[1]
                if dst in reg32 and src in reg32:
                    modrm = 0xC0 | (reg32[src] << 3) | reg32[dst]
                    return {'success': True, 'bytes': [0x31, modrm], 'error': None}
                if is_64bit and dst in reg64 and src in reg64:
                    d, s = reg64[dst], reg64[src]
                    rex = 0x48 | ((s >> 3) << 2) | (d >> 3)
                    modrm = 0xC0 | ((s & 7) << 3) | (d & 7)
                    return {'success': True, 'bytes': [rex, 0x31, modrm], 'error': None}
            
            # ADD reg, reg / ADD reg, imm
            if mnemonic == 'add' and len(operands) >= 2:
                dst, src = operands[0], operands[1]
                if dst in reg32 and src in reg32:
                    modrm = 0xC0 | (reg32[src] << 3) | reg32[dst]
                    return {'success': True, 'bytes': [0x01, modrm], 'error': None}
                if dst in reg32:
                    try:
                        imm = self.parse_number(src)
                        if dst == 'eax':
                            return {'success': True, 'bytes': [0x05] + list(struct.pack('<I', imm & 0xFFFFFFFF)), 'error': None}
                        if -128 <= imm <= 127:
                            modrm = 0xC0 | reg32[dst]
                            return {'success': True, 'bytes': [0x83, modrm, imm & 0xFF], 'error': None}
                    except:
                        pass
            
            # SUB reg, reg / SUB reg, imm
            if mnemonic == 'sub' and len(operands) >= 2:
                dst, src = operands[0], operands[1]
                if dst in reg32 and src in reg32:
                    modrm = 0xC0 | (reg32[src] << 3) | reg32[dst]
                    return {'success': True, 'bytes': [0x29, modrm], 'error': None}
                if dst in reg32:
                    try:
                        imm = self.parse_number(src)
                        if dst == 'eax':
                            return {'success': True, 'bytes': [0x2D] + list(struct.pack('<I', imm & 0xFFFFFFFF)), 'error': None}
                        if -128 <= imm <= 127:
                            modrm = 0xC0 | (5 << 3) | reg32[dst]
                            return {'success': True, 'bytes': [0x83, modrm, imm & 0xFF], 'error': None}
                    except:
                        pass
            
            # INC reg32
            if mnemonic == 'inc' and operands:
                if operands[0] in reg32:
                    if is_64bit:
                        modrm = 0xC0 | reg32[operands[0]]
                        return {'success': True, 'bytes': [0xFF, modrm], 'error': None}
                    return {'success': True, 'bytes': [0x40 + reg32[operands[0]]], 'error': None}
            
            # DEC reg32
            if mnemonic == 'dec' and operands:
                if operands[0] in reg32:
                    if is_64bit:
                        modrm = 0xC8 | reg32[operands[0]]
                        return {'success': True, 'bytes': [0xFF, modrm], 'error': None}
                    return {'success': True, 'bytes': [0x48 + reg32[operands[0]]], 'error': None}
            
            # CALL rel32
            if mnemonic == 'call':
                try:
                    target = self.parse_number(operands[0])
                    rel = target - (addr + 5)
                    return {'success': True, 'bytes': [0xE8] + list(struct.pack('<i', rel)), 'error': None}
                except:
                    pass
            
            # JMP rel8/rel32
            if mnemonic == 'jmp':
                try:
                    target = self.parse_number(operands[0])
                    rel = target - (addr + 2)
                    if -128 <= rel <= 127:
                        return {'success': True, 'bytes': [0xEB, rel & 0xFF], 'error': None}
                    rel = target - (addr + 5)
                    return {'success': True, 'bytes': [0xE9] + list(struct.pack('<i', rel)), 'error': None}
                except:
                    pass
            
            # Conditional jumps (short)
            jcc_map = {'je': 0x74, 'jz': 0x74, 'jne': 0x75, 'jnz': 0x75,
                      'jl': 0x7C, 'jge': 0x7D, 'jle': 0x7E, 'jg': 0x7F,
                      'ja': 0x77, 'jae': 0x73, 'jb': 0x72, 'jbe': 0x76,
                      'js': 0x78, 'jns': 0x79, 'jo': 0x70, 'jno': 0x71}
            if mnemonic in jcc_map:
                try:
                    target = self.parse_number(operands[0])
                    rel = target - (addr + 2)
                    if -128 <= rel <= 127:
                        return {'success': True, 'bytes': [jcc_map[mnemonic], rel & 0xFF], 'error': None}
                except:
                    pass
            
            # CMP reg, reg / CMP reg, imm
            if mnemonic == 'cmp' and len(operands) >= 2:
                dst, src = operands[0], operands[1]
                if dst in reg32 and src in reg32:
                    modrm = 0xC0 | (reg32[src] << 3) | reg32[dst]
                    return {'success': True, 'bytes': [0x39, modrm], 'error': None}
                if dst in reg32:
                    try:
                        imm = self.parse_number(src)
                        if -128 <= imm <= 127:
                            modrm = 0xC0 | (7 << 3) | reg32[dst]
                            return {'success': True, 'bytes': [0x83, modrm, imm & 0xFF], 'error': None}
                    except:
                        pass
            
            # TEST reg, reg
            if mnemonic == 'test' and len(operands) >= 2:
                dst, src = operands[0], operands[1]
                if dst in reg32 and src in reg32:
                    modrm = 0xC0 | (reg32[src] << 3) | reg32[dst]
                    return {'success': True, 'bytes': [0x85, modrm], 'error': None}
            
            # LEA reg, [reg+offset] - simplified
            if mnemonic == 'lea':
                # Very simplified - just handle lea reg, [reg]
                pass
            
            # SYSCALL (x64)
            if mnemonic == 'syscall' and is_64bit:
                return {'success': True, 'bytes': [0x0F, 0x05], 'error': None}
            
            # SYSENTER (x86)
            if mnemonic == 'sysenter':
                return {'success': True, 'bytes': [0x0F, 0x34], 'error': None}
            
            # CPUID
            if mnemonic == 'cpuid':
                return {'success': True, 'bytes': [0x0F, 0xA2], 'error': None}
            
            # RDTSC
            if mnemonic == 'rdtsc':
                return {'success': True, 'bytes': [0x0F, 0x31], 'error': None}
            
            # HLT
            if mnemonic == 'hlt':
                return {'success': True, 'bytes': [0xF4], 'error': None}
            
            # CLC, STC, CLI, STI
            if mnemonic == 'clc': return {'success': True, 'bytes': [0xF8], 'error': None}
            if mnemonic == 'stc': return {'success': True, 'bytes': [0xF9], 'error': None}
            if mnemonic == 'cli': return {'success': True, 'bytes': [0xFA], 'error': None}
            if mnemonic == 'sti': return {'success': True, 'bytes': [0xFB], 'error': None}
            if mnemonic == 'cld': return {'success': True, 'bytes': [0xFC], 'error': None}
            if mnemonic == 'std': return {'success': True, 'bytes': [0xFD], 'error': None}
            
            # LEAVE
            if mnemonic == 'leave':
                return {'success': True, 'bytes': [0xC9], 'error': None}
            
            # PUSHAD/POPAD (x86 only)
            if mnemonic == 'pushad' and not is_64bit:
                return {'success': True, 'bytes': [0x60], 'error': None}
            if mnemonic == 'popad' and not is_64bit:
                return {'success': True, 'bytes': [0x61], 'error': None}
            
            # PUSHFD/POPFD
            if mnemonic in ['pushfd', 'pushfq']:
                return {'success': True, 'bytes': [0x9C], 'error': None}
            if mnemonic in ['popfd', 'popfq']:
                return {'success': True, 'bytes': [0x9D], 'error': None}
            
            # DB (define byte)
            if mnemonic == 'db':
                bytes_out = []
                for op in operands:
                    bytes_out.append(self.parse_number(op) & 0xFF)
                return {'success': True, 'bytes': bytes_out, 'error': None}
            
            # DW (define word)
            if mnemonic == 'dw':
                bytes_out = []
                for op in operands:
                    val = self.parse_number(op) & 0xFFFF
                    bytes_out.extend([val & 0xFF, (val >> 8) & 0xFF])
                return {'success': True, 'bytes': bytes_out, 'error': None}
            
            # DD (define dword)
            if mnemonic == 'dd':
                bytes_out = []
                for op in operands:
                    val = self.parse_number(op) & 0xFFFFFFFF
                    bytes_out.extend(list(struct.pack('<I', val)))
                return {'success': True, 'bytes': bytes_out, 'error': None}
            
            return {'success': False, 'error': f'Unknown instruction: {mnemonic}', 'bytes': []}
            
        except Exception as e:
            return {'success': False, 'error': str(e), 'bytes': []}
    
    def parse_number(self, s):
        """Parse a number from string (hex or decimal)"""
        s = s.strip().lower()
        if s.startswith('0x'):
            return int(s, 16)
        elif s.endswith('h'):
            return int(s[:-1], 16)
        else:
            return int(s)
    
    def copy_hex_address(self):
        """Copy the address from right-click position in hex editor"""
        if self.hex_click_offset is not None:
            self.copy_to_clipboard(f"0x{self.hex_click_offset:08X}")
            self.update_status(f"Copied address: 0x{self.hex_click_offset:08X}")
        else:
            self.update_status("Could not determine address")
    
    def copy_hex_byte(self):
        """Copy the byte value at right-click position in hex editor"""
        if self.hex_click_offset is not None and self.hex_click_offset < len(self.data):
            byte_val = self.data[self.hex_click_offset]
            self.copy_to_clipboard(f"{byte_val:02X}")
            self.update_status(f"Copied byte: {byte_val:02X} at offset 0x{self.hex_click_offset:08X}")
        else:
            self.update_status("Could not get byte value")
    
    def copy_hex_selection(self):
        """Copy selected bytes from hex editor"""
        try:
            # Try to get selection from text widget
            sel_text = self.text_widget.get("sel.first", "sel.last")
            if sel_text:
                # Clean up - remove spaces and newlines, keep only hex chars
                cleaned = ''.join(c for c in sel_text.upper() if c in '0123456789ABCDEF')
                if cleaned:
                    self.copy_to_clipboard(cleaned)
                    self.update_status(f"Copied: {cleaned[:40]}{'...' if len(cleaned) > 40 else ''}")
                    return
        except tk.TclError:
            pass
        
        # If no selection, copy the byte at click position
        self.copy_hex_byte()
    
    def copy_asm_address(self):
        """Copy the address from the selected line in assembler output"""
        try:
            self.asm_output.config(state=tk.NORMAL)
            sel_start = self.asm_output.index("sel.first")
            line_text = self.asm_output.get(f"{sel_start} linestart", f"{sel_start} lineend")
            self.asm_output.config(state=tk.DISABLED)
            
            # Address is the first 8 characters
            if len(line_text) >= 8:
                address = line_text[:8].strip()
                if address and not address.startswith(';'):
                    self.copy_to_clipboard(f"0x{address}")
                    self.update_status(f"Copied address: 0x{address}")
        except:
            self.update_status("No line selected")
    
    def copy_asm_line_bytes(self):
        """Copy the bytes from the selected line in assembler output"""
        try:
            self.asm_output.config(state=tk.NORMAL)
            sel_start = self.asm_output.index("sel.first")
            line_text = self.asm_output.get(f"{sel_start} linestart", f"{sel_start} lineend")
            self.asm_output.config(state=tk.DISABLED)
            
            # Bytes are between positions 10 and 34 (after address and spaces)
            if len(line_text) >= 10:
                bytes_part = line_text[10:34].strip()
                if bytes_part and bytes_part != "ERROR":
                    # Remove spaces for compact hex
                    compact_bytes = bytes_part.replace(" ", "")
                    self.copy_to_clipboard(compact_bytes)
                    self.update_status(f"Copied bytes: {compact_bytes}")
        except:
            self.update_status("No line selected")
    
    def copy_asm_line(self):
        """Copy the entire selected line in assembler output"""
        try:
            self.asm_output.config(state=tk.NORMAL)
            sel_start = self.asm_output.index("sel.first")
            line_text = self.asm_output.get(f"{sel_start} linestart", f"{sel_start} lineend")
            self.asm_output.config(state=tk.DISABLED)
            
            if line_text.strip():
                self.copy_to_clipboard(line_text)
                self.update_status("Copied line to clipboard")
        except:
            self.update_status("No line selected")
    
    def copy_assembled_bytes(self):
        """Copy assembled bytes to clipboard"""
        if self.assembled_bytes:
            hex_str = self.assembled_bytes.hex().upper()
            self.copy_to_clipboard(hex_str)
            self.update_status(f"Copied {len(self.assembled_bytes)} bytes to clipboard")
        else:
            self.update_status("No assembled bytes to copy")
    
    def inject_assembled_bytes(self):
        """Inject assembled bytes at current selection/cursor position"""
        if not self.assembled_bytes:
            messagebox.showwarning("No Bytes", "Please assemble code first.")
            return
        
        if not self.data:
            messagebox.showwarning("No File", "Please open a file first.")
            return
        
        # Get current offset from editing_offset or prompt user
        if self.editing_offset is not None:
            offset = self.editing_offset
        else:
            # Show dialog to get offset
            dialog = tk.Toplevel(self.root)
            dialog.title("Inject Bytes")
            dialog.geometry("300x150")
            dialog.transient(self.root)
            dialog.grab_set()
            
            tk.Label(dialog, text=f"Inject {len(self.assembled_bytes)} bytes at offset:", 
                    font=("Arial", 10)).pack(pady=10)
            
            offset_var = tk.StringVar(value="0x00000000")
            offset_entry = tk.Entry(dialog, textvariable=offset_var, font=("Courier", 12), width=15)
            offset_entry.pack(pady=5)
            offset_entry.select_range(0, tk.END)
            offset_entry.focus()
            
            result = {'offset': None}
            
            def do_inject():
                try:
                    result['offset'] = int(offset_var.get(), 16) if offset_var.get().startswith("0x") else int(offset_var.get())
                    dialog.destroy()
                except ValueError:
                    messagebox.showerror("Invalid Offset", "Please enter a valid hex or decimal offset.")
            
            tk.Button(dialog, text="Inject", command=do_inject, bg="#FF5722", fg="white", 
                     font=("Arial", 10, "bold")).pack(pady=10)
            
            dialog.wait_window()
            offset = result['offset']
        
        if offset is None:
            return
        
        if offset < 0 or offset + len(self.assembled_bytes) > len(self.data):
            messagebox.showerror("Invalid Offset", 
                               f"Offset 0x{offset:X} is out of range. File size: {len(self.data)} bytes")
            return
        
        # Inject the bytes
        for i, b in enumerate(self.assembled_bytes):
            self.data[offset + i] = b
        
        self.modified = True
        self.display_hex()
        self.highlight_changes(offset, len(self.assembled_bytes))
        self.update_status(f"Injected {len(self.assembled_bytes)} bytes at offset 0x{offset:08X}")

    def update_status(self, message):
        self.status_bar.config(text=message)
    
    def exit_app(self):
        if self.modified:
            response = messagebox.askyesnocancel("Save Changes", 
                                                  "Do you want to save changes before exiting?")
            if response is None:  # Cancel
                return
            elif response:  # Yes
                self.save_file()
        
        self.root.quit()


def main():
    root = tk.Tk()
    app = HexEditor(root)
    root.mainloop()


if __name__ == "__main__":
    main()
