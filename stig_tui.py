#!/usr/bin/env python3
"""
DISA STIG to Markdown Converter - Text User Interface (TUI)

This module provides a terminal-based graphical interface for the STIG converter.
Requires: pip install textual

Usage:
    python stig_to_markdown.py --tui
    python stig_tui.py
"""

from pathlib import Path
from typing import Optional, Set, List

from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Container, Horizontal, Vertical, VerticalScroll
from textual.screen import ModalScreen
from textual.widgets import (
    Button,
    Checkbox,
    DataTable,
    DirectoryTree,
    Footer,
    Header,
    Input,
    ProgressBar,
    Static,
    TabbedContent,
    TabPane,
)

# Import core functionality from main module
from stig_to_markdown import (
    parse_xccdf,
    convert_to_markdown,
    find_xccdf_file,
    normalize_severity_list,
    filter_rules_by_severity,
    get_severity_suffix,
    load_stig,
    get_stig_short_name,
    search_rules,
    StigBenchmark,
    StigRule,
)

# Default STIG directory
DEFAULT_STIG_DIR = Path("./stigs")


# CSS Styling for the TUI
CSS = """
Screen {
    background: $surface;
}

#main-container {
    width: 100%;
    height: 100%;
    padding: 1 2;
}

#title-bar {
    width: 100%;
    height: 3;
    background: $primary;
    color: $text;
    text-align: center;
    padding: 1;
    text-style: bold;
}

.section {
    width: 100%;
    height: auto;
    margin: 1 0;
    padding: 1;
    border: solid $primary;
}

.section-title {
    text-style: bold;
    color: $secondary;
    margin-bottom: 1;
}

#file-section {
    height: auto;
}

#severity-section {
    height: auto;
}

#preview-section {
    height: auto;
    min-height: 8;
}

#preview-content {
    padding: 0 1;
}

.input-row {
    width: 100%;
    height: 3;
    margin-bottom: 1;
}

.input-label {
    width: 15;
    height: 3;
    padding: 1 1 0 0;
}

.input-field {
    width: 1fr;
}

#severity-checkboxes {
    width: 100%;
    height: auto;
    layout: horizontal;
}

.severity-checkbox {
    width: auto;
    margin-right: 3;
}

#button-row {
    width: 100%;
    height: 5;
    align: center middle;
    margin-top: 1;
}

#search-btn {
    width: 20;
    margin-right: 2;
}

#convert-btn {
    width: 30;
    margin-right: 2;
}

#quit-btn {
    width: 15;
}

#status-bar {
    width: 100%;
    height: 3;
    background: $surface-darken-1;
    padding: 1;
    dock: bottom;
}

.success {
    color: $success;
}

.error {
    color: $error;
}

.warning {
    color: $warning;
}

/* File Browser Modal */
FileBrowserScreen {
    align: center middle;
}

#file-browser-container {
    width: 80%;
    height: 80%;
    border: thick $primary;
    background: $surface;
    padding: 1;
}

#file-browser-title {
    text-style: bold;
    text-align: center;
    padding: 1;
    background: $primary;
}

#file-tree {
    height: 1fr;
    border: solid $secondary;
}

#file-browser-buttons {
    height: 3;
    align: center middle;
    margin-top: 1;
}

#selected-file-label {
    height: 3;
    padding: 1;
    background: $surface-darken-1;
}

/* Help Modal */
HelpScreen {
    align: center middle;
}

#help-container {
    width: 60;
    height: auto;
    max-height: 80%;
    border: thick $primary;
    background: $surface;
    padding: 1;
}

#help-title {
    text-style: bold;
    text-align: center;
    padding: 1;
    background: $primary;
}

#help-content {
    padding: 1 2;
}

.help-section {
    margin-bottom: 1;
}

.help-key {
    color: $secondary;
    text-style: bold;
}

#help-buttons {
    height: 3;
    align: center middle;
    margin-top: 1;
}

/* Progress Modal */
ProgressScreen {
    align: center middle;
}

#progress-container {
    width: 60;
    height: 12;
    border: thick $primary;
    background: $surface;
    padding: 2;
}

#progress-title {
    text-align: center;
    text-style: bold;
    margin-bottom: 1;
}

#progress-status {
    text-align: center;
    margin-bottom: 1;
}

#progress-bar {
    width: 100%;
    margin: 1 0;
}

/* Results Modal */
ResultsScreen {
    align: center middle;
}

#results-container {
    width: 70;
    height: auto;
    max-height: 80%;
    border: thick $primary;
    background: $surface;
    padding: 2;
}

#results-title {
    text-align: center;
    text-style: bold;
    margin-bottom: 1;
}

#results-content {
    margin: 1 0;
    padding: 1;
    background: $surface-darken-1;
}

#results-buttons {
    height: 3;
    align: center middle;
    margin-top: 1;
}

/* Search Modal */
SearchScreen {
    align: center middle;
}

#search-container {
    width: 90%;
    height: 85%;
    border: thick $primary;
    background: $surface;
    padding: 1;
}

#search-header {
    height: auto;
    padding: 1;
    background: $primary;
}

#search-title {
    text-style: bold;
    text-align: center;
}

#search-input-row {
    height: 3;
    margin: 1 0;
}

#search-input {
    width: 1fr;
}

#search-results-container {
    height: 1fr;
    margin: 1 0;
}

#search-results {
    height: 100%;
}

#search-hint {
    height: 3;
    padding: 1;
    background: $surface-darken-1;
}

#search-buttons {
    height: 3;
    align: center middle;
}

#search-results {
    height: 100%;
    width: 100%;
}

#search-results > .datatable--header {
    background: $primary;
}

#search-hint {
    color: $text-muted;
    text-style: italic;
    padding: 1;
}

#no-results {
    padding: 2;
    text-align: center;
    color: $text-muted;
}

/* STIG Detail Modal */
StigDetailScreen {
    align: center middle;
}

#detail-container {
    width: 90%;
    height: 90%;
    border: thick $primary;
    background: $surface;
}

#detail-header {
    height: auto;
    padding: 1;
    background: $primary;
}

#detail-title {
    text-style: bold;
    text-align: center;
}

#detail-meta {
    height: auto;
    padding: 1;
    background: $surface-darken-1;
}

#detail-content {
    height: 1fr;
    padding: 1;
}

#desc-text, #check-text, #fix-text {
    padding: 1 2;
    width: 100%;
}

#detail-buttons {
    height: 3;
    align: center middle;
    padding: 1;
    background: $surface-darken-1;
}

.severity-high {
    color: #ff6b6b;
}

.severity-medium {
    color: #ffa94d;
}

.severity-low {
    color: #ffe066;
}

/* Tabs */
TabbedContent {
    height: 1fr;
}

TabPane {
    padding: 1;
    overflow-y: auto;
}
"""


class FilteredDirectoryTree(DirectoryTree):
    """Directory tree that shows only zip files and directories."""
    
    def filter_paths(self, paths):
        """Filter to show only directories and zip files."""
        return [
            path for path in paths
            if path.is_dir() or path.suffix.lower() == '.zip'
        ]


class FileBrowserScreen(ModalScreen[Optional[Path]]):
    """Modal screen for browsing and selecting files."""
    
    BINDINGS = [
        Binding("escape", "cancel", "Cancel"),
        Binding("enter", "select", "Select"),
    ]
    
    def __init__(self, start_path: str = ".", select_directory: bool = False):
        super().__init__()
        self.start_path = Path(start_path).expanduser().resolve()
        self.select_directory = select_directory
        self.selected_path: Optional[Path] = None
    
    def compose(self) -> ComposeResult:
        with Container(id="file-browser-container"):
            yield Static(
                "Select Output Directory" if self.select_directory else "Select STIG Zip File",
                id="file-browser-title"
            )
            if self.select_directory:
                yield DirectoryTree(str(self.start_path), id="file-tree")
            else:
                yield FilteredDirectoryTree(str(self.start_path), id="file-tree")
            yield Static("No file selected", id="selected-file-label")
            with Horizontal(id="file-browser-buttons"):
                yield Button("Select", variant="primary", id="select-btn")
                yield Button("Cancel", variant="default", id="cancel-btn")
    
    @on(DirectoryTree.FileSelected)
    def on_file_selected(self, event: DirectoryTree.FileSelected) -> None:
        """Handle file selection in tree."""
        self.selected_path = event.path
        label = self.query_one("#selected-file-label", Static)
        label.update(f"Selected: {event.path.name}")
    
    @on(DirectoryTree.DirectorySelected)
    def on_directory_selected(self, event: DirectoryTree.DirectorySelected) -> None:
        """Handle directory selection in tree."""
        if self.select_directory:
            self.selected_path = event.path
            label = self.query_one("#selected-file-label", Static)
            label.update(f"Selected: {event.path}")
    
    @on(Button.Pressed, "#select-btn")
    def action_select(self) -> None:
        """Confirm selection and close modal."""
        if self.selected_path:
            self.dismiss(self.selected_path)
        elif self.select_directory:
            # Use current directory if none selected
            tree = self.query_one("#file-tree", DirectoryTree)
            self.dismiss(Path(tree.path))
    
    @on(Button.Pressed, "#cancel-btn")
    def action_cancel(self) -> None:
        """Cancel and close modal."""
        self.dismiss(None)


class ProgressScreen(ModalScreen):
    """Modal screen showing conversion progress."""
    
    def __init__(self, message: str = "Processing..."):
        super().__init__()
        self.message = message
    
    def compose(self) -> ComposeResult:
        with Container(id="progress-container"):
            yield Static("Converting STIG", id="progress-title")
            yield Static(self.message, id="progress-status")
            yield ProgressBar(id="progress-bar", show_eta=False)
    
    def update_status(self, message: str, progress: float = None):
        """Update the status message and optionally progress."""
        status = self.query_one("#progress-status", Static)
        status.update(message)
        if progress is not None:
            bar = self.query_one("#progress-bar", ProgressBar)
            bar.update(progress=progress)


class HelpScreen(ModalScreen):
    """Modal screen showing help and keybindings."""
    
    BINDINGS = [
        Binding("escape", "close", "Close"),
        Binding("?", "close", "Close"),
        Binding("enter", "close", "Close"),
    ]
    
    def compose(self) -> ComposeResult:
        with Container(id="help-container"):
            yield Static("⌨️  Keyboard Shortcuts", id="help-title")
            
            with Vertical(id="help-content"):
                yield Static("[bold]Navigation[/bold]", classes="help-section")
                yield Static("  [help-key]Tab[/help-key]          Navigate between elements")
                yield Static("  [help-key]Shift+Tab[/help-key]    Navigate backwards")
                yield Static("  [help-key]Enter[/help-key]        Activate / Select")
                yield Static("  [help-key]Space[/help-key]        Toggle checkboxes")
                yield Static("")
                
                yield Static("[bold]Actions[/bold]", classes="help-section")
                yield Static("  [help-key]/[/help-key]            Open search")
                yield Static("  [help-key]?[/help-key]            Show this help")
                yield Static("  [help-key]F1[/help-key]           Show this help")
                yield Static("")
                
                yield Static("[bold]Quitting[/bold]", classes="help-section")
                yield Static("  [help-key]q[/help-key]            Quit application")
                yield Static("  [help-key]Escape[/help-key]       Close popup / Quit")
                yield Static("  [help-key]Ctrl+C[/help-key]       Quit application")
                yield Static("")
                
                yield Static("[bold]In Search Modal[/bold]", classes="help-section")
                yield Static("  [help-key]Enter[/help-key]        View selected STIG details")
                yield Static("  [help-key]↑ / ↓[/help-key]        Navigate results")
                yield Static("  [help-key]Escape[/help-key]       Close search")
            
            with Horizontal(id="help-buttons"):
                yield Button("Close", variant="primary", id="close-help-btn")
    
    @on(Button.Pressed, "#close-help-btn")
    def action_close(self) -> None:
        """Close the help modal."""
        self.dismiss()


class ResultsScreen(ModalScreen):
    """Modal screen showing conversion results."""
    
    BINDINGS = [
        Binding("escape", "close", "Close"),
        Binding("enter", "close", "Close"),
    ]
    
    def __init__(self, success: bool, message: str, details: str = ""):
        super().__init__()
        self.success = success
        self.message = message
        self.details = details
    
    def compose(self) -> ComposeResult:
        with Container(id="results-container"):
            title = "✅ Conversion Complete" if self.success else "❌ Conversion Failed"
            yield Static(title, id="results-title")
            yield Static(self.message, id="results-content", classes="success" if self.success else "error")
            if self.details:
                yield Static(self.details)
            with Horizontal(id="results-buttons"):
                yield Button("OK", variant="primary", id="ok-btn")
    
    @on(Button.Pressed, "#ok-btn")
    def action_close(self) -> None:
        """Close the results modal."""
        self.dismiss()


class SearchScreen(ModalScreen):
    """Modal screen for searching STIGs."""
    
    BINDINGS = [
        Binding("escape", "close", "Close"),
    ]
    
    def __init__(self, loaded_stigs: List[tuple]):
        super().__init__()
        self.loaded_stigs = loaded_stigs
    
    def compose(self) -> ComposeResult:
        with Container(id="search-container"):
            # Header
            with Vertical(id="search-header"):
                yield Static("🔍 Search STIGs", id="search-title")
            
            # Search input
            with Horizontal(id="search-input-row"):
                yield Input(
                    placeholder="Search by STIG ID, title, description, or CCI...",
                    id="search-input"
                )
                yield Button("Clear", id="clear-search-btn")
            
            # Results hint
            yield Static("Type to search. Press Enter on a result to view details.", id="search-hint")
            
            # Results table
            with Container(id="search-results-container"):
                yield DataTable(id="search-results", cursor_type="row")
            
            # Buttons
            with Horizontal(id="search-buttons"):
                yield Button("Close", variant="default", id="close-search-btn")
    
    def on_mount(self) -> None:
        """Initialize the search table when mounted."""
        self._init_search_table()
        self._update_search_results("")
        # Focus the search input
        self.query_one("#search-input", Input).focus()
    
    def _init_search_table(self) -> None:
        """Initialize the search results DataTable."""
        table = self.query_one("#search-results", DataTable)
        table.clear(columns=True)
        if len(self.loaded_stigs) > 1:
            table.add_columns("STIG", "STIG ID", "Severity", "Title")
        else:
            table.add_columns("STIG ID", "Severity", "Title")
        table.fixed_columns = 1
    
    def _update_search_results(self, query: str) -> None:
        """Update search results based on query."""
        if not self.loaded_stigs:
            return
        
        table = self.query_one("#search-results", DataTable)
        table.clear()
        
        query_lower = query.lower().strip()
        
        # Collect matching rules from all STIGs
        matching_rules = []
        total_rules = 0
        
        for short_name, benchmark, _ in self.loaded_stigs:
            total_rules += len(benchmark.rules)
            matches = search_rules(benchmark, query, None) if query_lower else benchmark.rules
            for rule in matches:
                matching_rules.append((short_name, rule))
        
        # Sort by STIG name, then by STIG ID
        matching_rules.sort(key=lambda x: (x[0], x[1].stig_id))
        
        # Populate table
        severity_display = {
            'high': '🔴 CAT I',
            'medium': '🟠 CAT II',
            'low': '🟡 CAT III'
        }
        
        multi_stig = len(self.loaded_stigs) > 1
        
        for short_name, rule in matching_rules[:200]:  # Limit to 200 results
            sev = severity_display.get(rule.severity.lower(), rule.severity)
            title_max = 55 if multi_stig else 70
            title = rule.title[:title_max] + "..." if len(rule.title) > title_max else rule.title
            
            row_key = f"{short_name}:{rule.stig_id}"
            
            if multi_stig:
                table.add_row(short_name, rule.stig_id, sev, title, key=row_key)
            else:
                table.add_row(rule.stig_id, sev, title, key=row_key)
        
        # Update hint
        hint = self.query_one("#search-hint", Static)
        shown = min(len(matching_rules), 200)
        
        if query_lower:
            if len(matching_rules) > 200:
                hint.update(f"Showing {shown} of {len(matching_rules)} matches. Refine search to see more.")
            elif len(matching_rules) == 0:
                hint.update("No matches found. Try a different search term.")
            else:
                hint.update(f"Found {len(matching_rules)} matches. Press Enter to view details.")
        else:
            hint.update(f"Showing {shown} of {total_rules} rules. Type to filter.")
    
    @on(Input.Changed, "#search-input")
    def on_search_changed(self, event: Input.Changed) -> None:
        """Handle search input changes."""
        self._update_search_results(event.value)
    
    @on(Button.Pressed, "#clear-search-btn")
    def clear_search(self) -> None:
        """Clear the search input."""
        search_input = self.query_one("#search-input", Input)
        search_input.value = ""
        self._update_search_results("")
        search_input.focus()
    
    @on(DataTable.RowSelected, "#search-results")
    def on_row_selected(self, event: DataTable.RowSelected) -> None:
        """Handle row selection - show STIG detail."""
        row_key = event.row_key.value
        if not row_key:
            return
        
        # Parse the row key
        if ':' in row_key:
            short_name, stig_id = row_key.split(':', 1)
        else:
            stig_id = row_key
            short_name = None
        
        # Find the rule
        rule = None
        for name, benchmark, _ in self.loaded_stigs:
            if short_name and name != short_name:
                continue
            for r in benchmark.rules:
                if r.stig_id == stig_id:
                    rule = r
                    break
            if rule:
                break
        
        if rule:
            self.app.push_screen(StigDetailScreen(rule))
    
    @on(Button.Pressed, "#close-search-btn")
    def action_close(self) -> None:
        """Close the search modal."""
        self.dismiss()


class StigDetailScreen(ModalScreen):
    """Modal screen showing detailed STIG rule information."""
    
    BINDINGS = [
        Binding("escape", "close", "Close"),
        Binding("q", "close", "Close"),
    ]
    
    def __init__(self, rule: StigRule):
        super().__init__()
        self.rule = rule
    
    def compose(self) -> ComposeResult:
        # Determine severity class
        severity_class = f"severity-{self.rule.severity.lower()}"
        severity_text = {
            'high': '🔴 CAT I (High)',
            'medium': '🟠 CAT II (Medium)',
            'low': '🟡 CAT III (Low)'
        }.get(self.rule.severity.lower(), self.rule.severity)
        
        with Container(id="detail-container"):
            # Header
            with Vertical(id="detail-header"):
                yield Static(f"[bold]{self.rule.stig_id}[/bold]", id="detail-title")
                yield Static(self.rule.title)
            
            # Metadata
            with Horizontal(id="detail-meta"):
                yield Static(f"[bold]Severity:[/bold] [{severity_class}]{severity_text}[/{severity_class}]")
                yield Static(f"  |  [bold]Rule ID:[/bold] {self.rule.rule_id}")
                if self.rule.cci_refs:
                    yield Static(f"  |  [bold]CCI:[/bold] {', '.join(self.rule.cci_refs[:3])}")
            
            # Content with tabs
            with TabbedContent():
                with TabPane("Description", id="tab-desc"):
                    yield Static(self._format_description_text(), markup=True, id="desc-text")
                with TabPane("Check", id="tab-check"):
                    yield Static(self._format_check_text(), markup=True, id="check-text")
                with TabPane("Fix", id="tab-fix"):
                    yield Static(self._format_fix_text(), markup=True, id="fix-text")
            
            # Buttons
            with Horizontal(id="detail-buttons"):
                yield Button("Close", variant="primary", id="close-btn")
    
    def _format_description_text(self) -> str:
        """Format the vulnerability description using Rich markup."""
        cci_refs = ', '.join(self.rule.cci_refs) if self.rule.cci_refs else 'None'
        legacy_ids = ', '.join(self.rule.legacy_ids) if self.rule.legacy_ids else 'None'
        
        # Escape any Rich markup in the description
        desc = self.rule.description.replace('[', '\\[').replace(']', '\\]')
        
        return f"""[bold underline]Vulnerability Discussion[/bold underline]

{desc}

─────────────────────────────────────────

[bold]Additional Information:[/bold]
  • [bold]STIG ID:[/bold] {self.rule.stig_id}
  • [bold]Rule ID:[/bold] {self.rule.rule_id}
  • [bold]CCI References:[/bold] {cci_refs}
  • [bold]Legacy IDs:[/bold] {legacy_ids}
"""
    
    def _format_check_text(self) -> str:
        """Format the check procedure using Rich markup."""
        # Escape any Rich markup in the check text
        check = self.rule.check_text.replace('[', '\\[').replace(']', '\\]')
        
        return f"""[bold underline]Check Procedure[/bold underline]

{check}
"""
    
    def _format_fix_text(self) -> str:
        """Format the fix procedure using Rich markup."""
        # Escape any Rich markup in the fix text
        fix = self.rule.fix_text.replace('[', '\\[').replace(']', '\\]')
        
        return f"""[bold underline]Fix Procedure[/bold underline]

{fix}
"""
    
    @on(Button.Pressed, "#close-btn")
    def action_close(self) -> None:
        """Close the detail modal."""
        self.dismiss()


class StigConverterApp(App):
    """Main TUI application for STIG to Markdown conversion."""
    
    TITLE = "DISA STIG to Markdown Converter"
    CSS = CSS
    
    BINDINGS = [
        Binding("q", "quit", "Quit"),
        Binding("escape", "quit", "Quit", show=False),
        Binding("ctrl+c", "quit", "Quit"),
        Binding("f1", "help", "Help"),
        Binding("question_mark", "help", "Help", key_display="?"),
        Binding("/", "focus_search", "Search"),
    ]
    
    def __init__(self):
        super().__init__()
        self.output_dir: Path = Path.cwd()
        # Support multiple loaded STIGs: list of (short_name, benchmark, file_path) tuples
        self.loaded_stigs: List[tuple] = []
    
    def compose(self) -> ComposeResult:
        yield Header()
        
        with VerticalScroll(id="main-container"):
            # Loaded STIGs Section
            with Vertical(classes="section", id="file-section"):
                yield Static("📁 Loaded STIGs", classes="section-title")
                yield Static("Loading...", id="loaded-stigs-list")
                with Horizontal(classes="input-row"):
                    yield Static("Add STIG:", classes="input-label")
                    yield Input(placeholder="Enter path or click Browse...", id="stig-input", classes="input-field")
                    yield Button("Browse", id="browse-stig-btn")
                    yield Button("Add", id="add-stig-btn", variant="primary")
                
                with Horizontal(classes="input-row"):
                    yield Static("Output Dir:", classes="input-label")
                    yield Input(placeholder=str(self.output_dir), id="output-input", classes="input-field")
                    yield Button("Browse", id="browse-output-btn")
            
            # Severity Filter Section
            with Vertical(classes="section", id="severity-section"):
                yield Static("🎯 Severity Filter", classes="section-title")
                with Horizontal(id="severity-checkboxes"):
                    yield Checkbox("CAT I (High)", value=True, id="cat1-checkbox", classes="severity-checkbox")
                    yield Checkbox("CAT II (Medium)", value=True, id="cat2-checkbox", classes="severity-checkbox")
                    yield Checkbox("CAT III (Low)", value=True, id="cat3-checkbox", classes="severity-checkbox")
            
            # Preview Section
            with Vertical(classes="section", id="preview-section"):
                yield Static("📋 STIG Preview", classes="section-title")
                yield Static("Select a STIG zip file to see preview...", id="preview-content")
            
            # Action Buttons
            with Horizontal(id="button-row"):
                yield Button("🔍 Search", variant="default", id="search-btn", disabled=True)
                yield Button("🔄 Convert to Markdown", variant="primary", id="convert-btn", disabled=True)
                yield Button("Quit", variant="default", id="quit-btn")
        
        yield Static("Ready", id="status-bar")
        yield Footer()
    
    def on_mount(self) -> None:
        """Called when the app is mounted - auto-load STIGs from default directory."""
        self._auto_load_stigs()
    
    @work(thread=True)
    def _auto_load_stigs(self) -> None:
        """Auto-load STIGs from the default directory."""
        if DEFAULT_STIG_DIR.exists() and DEFAULT_STIG_DIR.is_dir():
            zip_files = sorted(DEFAULT_STIG_DIR.glob("*.zip"))
            if zip_files:
                self.call_from_thread(
                    self.update_status,
                    f"Loading {len(zip_files)} STIG(s) from {DEFAULT_STIG_DIR}/...",
                    "yellow"
                )
                for zip_file in zip_files:
                    try:
                        benchmark = load_stig(str(zip_file))
                        short_name = get_stig_short_name(benchmark)
                        self.loaded_stigs.append((short_name, benchmark, zip_file))
                    except Exception as e:
                        self.call_from_thread(
                            self.update_status,
                            f"Failed to load {zip_file.name}: {e}",
                            "red"
                        )
                
                self.call_from_thread(self._update_loaded_stigs_display)
                self.call_from_thread(self._enable_features_if_loaded)
                self.call_from_thread(
                    self.update_status,
                    f"Loaded {len(self.loaded_stigs)} STIG(s) from {DEFAULT_STIG_DIR}/",
                    "green"
                )
            else:
                self.call_from_thread(
                    self._update_loaded_stigs_display_empty,
                    f"No STIG files found in {DEFAULT_STIG_DIR}/"
                )
        else:
            self.call_from_thread(
                self._update_loaded_stigs_display_empty,
                f"Default directory {DEFAULT_STIG_DIR}/ not found. Add STIGs manually."
            )
    
    def _update_loaded_stigs_display(self) -> None:
        """Update the display of loaded STIGs."""
        if not self.loaded_stigs:
            return
        
        lines = []
        total_rules = 0
        for short_name, benchmark, file_path in self.loaded_stigs:
            rule_count = len(benchmark.rules)
            total_rules += rule_count
            lines.append(f"  ✓ [bold]{short_name}[/bold]: {benchmark.title} ({rule_count} rules)")
        
        lines.append(f"\n[bold]Total: {len(self.loaded_stigs)} STIG(s), {total_rules} rules[/bold]")
        
        display = self.query_one("#loaded-stigs-list", Static)
        display.update("\n".join(lines))
    
    def _update_loaded_stigs_display_empty(self, message: str) -> None:
        """Update display when no STIGs are loaded."""
        display = self.query_one("#loaded-stigs-list", Static)
        display.update(f"[dim]{message}[/dim]")
    
    def _enable_features_if_loaded(self) -> None:
        """Enable search and convert if STIGs are loaded."""
        if self.loaded_stigs:
            self.query_one("#convert-btn", Button).disabled = False
            self.query_one("#search-btn", Button).disabled = False
            self._update_preview()
    
    def _update_preview(self) -> None:
        """Update the preview section with loaded STIG info."""
        if not self.loaded_stigs:
            self.update_preview("No STIGs loaded. Add STIGs above or place files in ./stigs/")
            return
        
        lines = []
        total_high = 0
        total_medium = 0
        total_low = 0
        
        for short_name, benchmark, _ in self.loaded_stigs:
            high = sum(1 for r in benchmark.rules if r.severity.lower() == 'high')
            medium = sum(1 for r in benchmark.rules if r.severity.lower() == 'medium')
            low = sum(1 for r in benchmark.rules if r.severity.lower() == 'low')
            total_high += high
            total_medium += medium
            total_low += low
        
        lines.append(f"[bold]Loaded {len(self.loaded_stigs)} STIG(s)[/bold]")
        lines.append("")
        lines.append("[bold]Combined Rules by Severity:[/bold]")
        lines.append(f"  🔴 CAT I (High):   {total_high:>4}")
        lines.append(f"  🟠 CAT II (Medium): {total_medium:>4}")
        lines.append(f"  🟡 CAT III (Low):   {total_low:>4}")
        lines.append(f"  ─────────────────────")
        lines.append(f"  [bold]Total:[/bold]            {total_high + total_medium + total_low:>4}")
        
        self.update_preview("\n".join(lines))
    
    def update_status(self, message: str, style: str = ""):
        """Update the status bar message."""
        status = self.query_one("#status-bar", Static)
        if style:
            status.update(f"[{style}]{message}[/{style}]")
        else:
            status.update(message)
    
    @on(Button.Pressed, "#browse-stig-btn")
    def browse_stig_file(self) -> None:
        """Open file browser for STIG zip selection."""
        self._do_browse_stig()
    
    @work(exclusive=True)
    async def _do_browse_stig(self) -> None:
        """Worker to handle STIG file browsing."""
        result = await self.push_screen_wait(
            FileBrowserScreen(start_path=".", select_directory=False)
        )
        if result:
            stig_input = self.query_one("#stig-input", Input)
            stig_input.value = str(result)
    
    @on(Button.Pressed, "#add-stig-btn")
    def add_stig_file(self) -> None:
        """Add a STIG file from the input."""
        stig_input = self.query_one("#stig-input", Input)
        if stig_input.value:
            self._add_stig(stig_input.value)
    
    @work(thread=True)
    def _add_stig(self, file_path: str) -> None:
        """Add a STIG file to the loaded list."""
        path = Path(file_path).expanduser()
        
        if not path.exists():
            self.call_from_thread(self.update_status, f"File not found: {path}", "red")
            return
        
        if path.suffix.lower() != '.zip':
            self.call_from_thread(self.update_status, "File must be a .zip file", "red")
            return
        
        # Check if already loaded
        for _, _, existing_path in self.loaded_stigs:
            if existing_path.resolve() == path.resolve():
                self.call_from_thread(self.update_status, f"STIG already loaded: {path.name}", "yellow")
                return
        
        self.call_from_thread(self.update_status, f"Loading {path.name}...", "yellow")
        
        try:
            benchmark = load_stig(str(path))
            short_name = get_stig_short_name(benchmark)
            self.loaded_stigs.append((short_name, benchmark, path))
            
            self.call_from_thread(self._update_loaded_stigs_display)
            self.call_from_thread(self._enable_features_if_loaded)
            self.call_from_thread(self._update_preview)
            self.call_from_thread(self._update_search_results, "")
            
            # Clear the input
            self.call_from_thread(self._clear_stig_input)
            self.call_from_thread(
                self.update_status,
                f"Added: {short_name} ({len(benchmark.rules)} rules)",
                "green"
            )
        except Exception as e:
            self.call_from_thread(self.update_status, f"Failed to load: {e}", "red")
    
    def _clear_stig_input(self) -> None:
        """Clear the STIG input field."""
        stig_input = self.query_one("#stig-input", Input)
        stig_input.value = ""
    
    @on(Button.Pressed, "#browse-output-btn")
    def browse_output_dir(self) -> None:
        """Open file browser for output directory selection."""
        self._do_browse_output()
    
    @work(exclusive=True)
    async def _do_browse_output(self) -> None:
        """Worker to handle output directory browsing."""
        result = await self.push_screen_wait(
            FileBrowserScreen(start_path=str(self.output_dir), select_directory=True)
        )
        if result:
            self.output_dir = result
            output_input = self.query_one("#output-input", Input)
            output_input.value = str(result)
    
    @on(Input.Submitted, "#stig-input")
    def on_stig_input_submitted(self, event: Input.Submitted) -> None:
        """Handle Enter key in STIG input - add the file."""
        if event.value:
            self._add_stig(event.value)
    
    @on(Input.Changed, "#output-input")
    def on_output_input_changed(self, event: Input.Changed) -> None:
        """Handle manual output directory path entry."""
        if event.value:
            self.output_dir = Path(event.value).expanduser()
        else:
            self.output_dir = Path.cwd()
    
    def update_preview(self, content: str) -> None:
        """Update the preview section content."""
        preview = self.query_one("#preview-content", Static)
        preview.update(content)
    
    @on(Button.Pressed, "#search-btn")
    def open_search(self) -> None:
        """Open the search modal."""
        if self.loaded_stigs:
            self.push_screen(SearchScreen(self.loaded_stigs))
    
    def get_selected_severities(self) -> Set[str]:
        """Get the set of selected severity levels."""
        severities = set()
        if self.query_one("#cat1-checkbox", Checkbox).value:
            severities.add("high")
        if self.query_one("#cat2-checkbox", Checkbox).value:
            severities.add("medium")
        if self.query_one("#cat3-checkbox", Checkbox).value:
            severities.add("low")
        return severities
    
    @on(Button.Pressed, "#convert-btn")
    def convert_stig(self) -> None:
        """Run the STIG to Markdown conversion."""
        if not self.loaded_stigs:
            return
        
        # Get selected severities
        severities = self.get_selected_severities()
        if not severities:
            self.push_screen(ResultsScreen(
                success=False,
                message="Please select at least one severity level"
            ))
            return
        
        # Start conversion in worker
        self._do_convert(severities)
    
    @work(exclusive=True, thread=True)
    def _do_convert(self, severities: Set[str]) -> None:
        """Worker to perform the actual conversion for all loaded STIGs."""
        # Show progress on main thread
        self.call_from_thread(self._show_progress)
        
        try:
            # Ensure output directory exists
            self.output_dir.mkdir(parents=True, exist_ok=True)
            
            # Apply severity filter if not all selected
            severity_filter = severities if len(severities) < 3 else None
            
            output_files = []
            total_stigs = len(self.loaded_stigs)
            
            for idx, (short_name, benchmark, file_path) in enumerate(self.loaded_stigs):
                progress = (idx + 0.5) / total_stigs
                self.call_from_thread(
                    self._update_progress,
                    f"Converting {short_name}... ({idx + 1}/{total_stigs})",
                    progress
                )
                
                # Convert to markdown
                markdown_content = convert_to_markdown(benchmark, severity_filter)
                
                # Generate output filename
                severity_suffix = get_severity_suffix(severity_filter) if severity_filter else ""
                output_filename = f"{file_path.stem}_STIG{severity_suffix}.md"
                output_file = self.output_dir / output_filename
                
                # Write file
                with open(output_file, 'w', encoding='utf-8') as f:
                    f.write(markdown_content)
                
                output_files.append((short_name, output_file, len(benchmark.rules)))
            
            self.call_from_thread(self._update_progress, "Complete!", 1.0)
            
            # Build details message
            total_rules = sum(count for _, _, count in output_files)
            details_lines = [f"Output directory: {self.output_dir}"]
            details_lines.append(f"Files created: {len(output_files)}")
            details_lines.append("")
            for short_name, output_file, rule_count in output_files:
                filtered_count = rule_count  # Would need to recalculate for filtered
                details_lines.append(f"  • {short_name}: {output_file.name}")
            
            if severity_filter:
                cat_names = {'high': 'CAT I', 'medium': 'CAT II', 'low': 'CAT III'}
                filtered_cats = ', '.join([cat_names[s] for s in sorted(severity_filter)])
                details_lines.append(f"\nFiltered by: {filtered_cats}")
            
            # Show results on main thread
            self.call_from_thread(
                self._show_results,
                True,
                f"Successfully created {len(output_files)} Markdown file(s)",
                "\n".join(details_lines),
                str(self.output_dir)
            )
            
        except Exception as e:
            self.call_from_thread(
                self._show_results,
                False,
                f"Conversion failed:\n{e}",
                "",
                ""
            )
    
    def _show_progress(self) -> None:
        """Show the progress screen."""
        self._progress_screen = ProgressScreen("Initializing...")
        self.push_screen(self._progress_screen)
    
    def _update_progress(self, message: str, progress: float) -> None:
        """Update progress screen."""
        if hasattr(self, '_progress_screen') and self._progress_screen:
            self._progress_screen.update_status(message, progress)
    
    def _show_results(self, success: bool, message: str, details: str, output_path: str) -> None:
        """Close progress and show results."""
        self.pop_screen()  # Close progress
        self.push_screen(ResultsScreen(success=success, message=message, details=details))
        if success and output_path:
            self.update_status(f"Saved: {output_path}", "green")
        elif not success:
            self.update_status(f"Error occurred", "red")
    
    @on(Button.Pressed, "#quit-btn")
    def quit_app(self) -> None:
        """Quit the application."""
        self.exit()
    
    def action_quit(self) -> None:
        """Quit action from key binding."""
        self.exit()
    
    def action_focus_search(self) -> None:
        """Open the search modal."""
        if self.loaded_stigs:
            self.push_screen(SearchScreen(self.loaded_stigs))
        else:
            self.notify("Load STIGs first to enable search.", title="No STIGs Loaded", timeout=5)
    
    def action_help(self) -> None:
        """Show help modal with keybindings."""
        self.push_screen(HelpScreen())


def run_tui():
    """Entry point for running the TUI."""
    app = StigConverterApp()
    app.run()


if __name__ == "__main__":
    run_tui()

