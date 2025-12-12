# DISA STIG to Markdown Converter

A Python utility that extracts DISA STIG (Security Technical Implementation Guide) zip files and converts the XCCDF XML content into readable Markdown documentation.

## Features

- **Interactive TUI Mode**: Beautiful terminal user interface for easy file selection and conversion
- **Command Line Mode**: Full CLI support for scripting and automation
- **Automated XCCDF Detection**: Automatically finds XCCDF files within STIG zip archives
- **Severity Filtering**: Filter output by CAT I, CAT II, and/or CAT III
- **Complete Rule Parsing**: Extracts all rule metadata including:
  - STIG IDs (V-numbers)
  - Severity (CAT I/II/III)
  - Vulnerability descriptions
  - Check procedures
  - Fix procedures
  - CCI references
  - Legacy IDs
- **Clean Markdown Output**: Generates well-formatted Markdown with:
  - Table of contents with anchor links
  - Severity statistics
  - Color-coded severity badges
  - Formatted code blocks for check/fix procedures
- **Minimal Dependencies**: CLI mode uses Python standard library only; TUI requires `textual`

## Requirements

- Python 3.7+
- **CLI Mode**: No external packages required (uses standard library)
- **TUI Mode**: Requires `textual` package

## Installation

```bash
# Clone or download the script
git clone <repository-url>
cd test-app

# CLI mode works out of the box - no installation needed

# For TUI mode, install textual:
pip install textual
# Or install all dependencies:
pip install -r requirements.txt
```

## Usage

### Interactive TUI Mode

Launch the interactive terminal user interface for a visual experience:

```bash
python stig_to_markdown.py --tui
```

The TUI provides:
- **Auto-loading** from `./stigs/` directory on startup
- **Multiple STIG support** - load and work with multiple STIGs at once
- **Search popup** - press `/` to search across all loaded STIGs
- **Severity filter** checkboxes (CAT I, CAT II, CAT III)
- **Live preview** of combined STIG statistics
- **Batch conversion** - convert all loaded STIGs at once

**Main Screen:**
```
┌─────────────────────────────────────────────────────────────────┐
│  DISA STIG to Markdown Converter                                │
├─────────────────────────────────────────────────────────────────┤
│  📁 Loaded STIGs                                                │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │   ✓ RHEL 9: Red Hat Enterprise Linux 9 STIG (447 rules)   │ │
│  │   ✓ Win 2022: Windows Server 2022 STIG (312 rules)        │ │
│  │                                                            │ │
│  │   Total: 2 STIG(s), 759 rules                             │ │
│  └────────────────────────────────────────────────────────────┘ │
│  Add STIG: [________________________] [Browse] [Add]            │
│  Output:   [./output_______________] [Browse]                   │
│                                                                 │
│  🎯 Severity Filter                                             │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ [x] CAT I (High)  [x] CAT II (Medium)  [ ] CAT III (Low)   │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                 │
│  📋 STIG Preview                                                │
│  ┌────────────────────────────────────────────────────────────┐ │
│  │ Loaded 2 STIG(s)                                           │ │
│  │ Combined Rules by Severity:                                │ │
│  │   🔴 CAT I (High):    45    🟠 CAT II (Medium): 623        │ │
│  │   🟡 CAT III (Low):   91    Total: 759                     │ │
│  └────────────────────────────────────────────────────────────┘ │
│                                                                 │
│       [🔍 Search]  [🔄 Convert to Markdown]  [Quit]             │
└─────────────────────────────────────────────────────────────────┘
```

**Search Popup (press `/`):**
```
┌─────────────────────────────────────────────────────────────────┐
│  🔍 Search STIGs                                                │
├─────────────────────────────────────────────────────────────────┤
│  [Search by STIG ID, title, description...______] [Clear]       │
│                                                                 │
│  Found 38 matches. Press Enter to view details.                 │
│  ┌─────────────────────────────────────────────────────────────┐│
│  │ STIG     │ STIG ID    │ Severity │ Title                    ││
│  │ RHEL 9   │ V-257984   │ 🔴 CAT I │ SSHD must not allow...   ││
│  │ RHEL 9   │ V-258094   │ 🔴 CAT I │ Must not allow blank...  ││
│  │ Win 2022 │ V-254269   │ 🟠 CAT II│ Must have password...    ││
│  └─────────────────────────────────────────────────────────────┘│
│                                                                 │
│                         [Close]                                 │
└─────────────────────────────────────────────────────────────────┘
```

**Help Popup (press `?`):**
```
┌──────────────────────────────────────────────────────┐
│  ⌨️  Keyboard Shortcuts                              │
├──────────────────────────────────────────────────────┤
│  Navigation                                          │
│    Tab          Navigate between elements            │
│    Shift+Tab    Navigate backwards                   │
│    Enter        Activate / Select                    │
│    Space        Toggle checkboxes                    │
│                                                      │
│  Actions                                             │
│    /            Open search                          │
│    ?            Show this help                       │
│    F1           Show this help                       │
│                                                      │
│  Quitting                                            │
│    q            Quit application                     │
│    Escape       Close popup / Quit                   │
│    Ctrl+C       Quit application                     │
│                                                      │
│  In Search Modal                                     │
│    Enter        View selected STIG details           │
│    ↑ / ↓        Navigate results                     │
│    Escape       Close search                         │
└──────────────────────────────────────────────────────┘
```

**TUI Keyboard Shortcuts:**

| Key | Action |
|-----|--------|
| `/` | Open search popup |
| `?` or `F1` | Show help popup |
| `Tab` / `Shift+Tab` | Navigate between elements |
| `Space` | Toggle checkboxes |
| `Enter` | Activate buttons / Select items |
| `Escape` | Close popup / Quit application |
| `q` | Quit application |
| `Ctrl+C` | Quit application |

**Auto-Loading STIGs:**

Place STIG zip files in the `./stigs/` directory and they will be automatically loaded when the TUI starts:

```bash
mkdir -p stigs
cp U_RHEL_9_STIG.zip U_Windows_2022_STIG.zip ./stigs/
python stig_to_markdown.py --tui
```

### CLI Mode (Basic Usage)

The tool automatically looks for STIG files in the `./stigs/` directory:

```bash
# Use STIGs from default ./stigs/ directory (no files needed)
python stig_to_markdown.py --list
python stig_to_markdown.py -q "password"
python stig_to_markdown.py -o ./output

# Or specify STIG file(s) explicitly
python stig_to_markdown.py U_RHEL_8_STIG.zip
python stig_to_markdown.py U_RHEL_8_STIG.zip -o ./output
python stig_to_markdown.py *.zip -o ./output
```

**Default Directory Setup:**
```bash
mkdir -p stigs
# Place your STIG zip files in ./stigs/
cp U_RHEL_9_STIG.zip U_Windows_2022_STIG.zip ./stigs/
```

### Working with Multiple STIGs

All commands support multiple STIG files. Results are grouped by STIG:

```bash
# Convert multiple STIGs to separate markdown files
python stig_to_markdown.py U_RHEL_9_STIG.zip U_Windows_STIG.zip -o ./output

# List CAT I rules from all STIGs
python stig_to_markdown.py *.zip --list -s high

# Search across multiple STIGs
python stig_to_markdown.py *.zip --search "password"

# Find a rule across multiple STIGs
python stig_to_markdown.py *.zip --info V-257984
```

**Example output (multi-STIG search):**
```
Loading 2 STIG file(s)...
  ✓ RHEL 9: Red Hat Enterprise Linux 9 STIG (447 rules)
  ✓ Win 2022: Windows Server 2022 STIG (312 rules)

Searching for: 'password'

================================================================================
  Red Hat Enterprise Linux 9 Security Technical Implementation Guide
================================================================================

STIG ID      Severity  Title
--------------------------------------------------------------------------------
V-257984     CAT I     RHEL 9 SSHD must not allow blank passwords.
...
Matches: 15

================================================================================
  Windows Server 2022 Security Technical Implementation Guide
================================================================================

STIG ID      Severity  Title
--------------------------------------------------------------------------------
V-254269     CAT II    Windows Server 2022 must have password complexity...
...
Matches: 23

================================================================================
Total: 38 match(es) across 2 STIG(s)
```

### Searching STIGs

Search through STIG rules without converting to Markdown:

```bash
# Search by keyword (searches ID, title, description, check/fix text, CCI)
python stig_to_markdown.py U_RHEL_8_STIG.zip --search "ssh"
python stig_to_markdown.py U_RHEL_8_STIG.zip -q "password"

# Search with severity filter
python stig_to_markdown.py U_RHEL_8_STIG.zip -q "authentication" -s high

# Search across multiple STIGs
python stig_to_markdown.py *.zip -q "firewall"
```

### Listing STIGs

List all STIG rules in the file(s):

```bash
# List all rules
python stig_to_markdown.py U_RHEL_8_STIG.zip --list

# List only CAT I (High) severity
python stig_to_markdown.py U_RHEL_8_STIG.zip -l -s high

# List CAT I from multiple STIGs
python stig_to_markdown.py *.zip --list -s high
```

### STIG Details

Get detailed information for a specific STIG rule:

```bash
# Show full details for a STIG by ID
python stig_to_markdown.py U_RHEL_8_STIG.zip --info V-257984
python stig_to_markdown.py U_RHEL_8_STIG.zip -i V-257984

# Search for a rule across multiple STIGs
python stig_to_markdown.py *.zip --info V-257984
```

This displays:
- Title and severity
- Rule ID and CCI references
- Vulnerability discussion
- Check procedure
- Fix procedure

### Filtering by Severity

Filter the output to include only specific severity levels:

```bash
# CAT I (High) only - critical findings
python stig_to_markdown.py U_RHEL_8_STIG.zip -s high
python stig_to_markdown.py U_RHEL_8_STIG.zip --severity cat1

# CAT II (Medium) only
python stig_to_markdown.py U_RHEL_8_STIG.zip -s medium
python stig_to_markdown.py U_RHEL_8_STIG.zip --severity 2

# Multiple severities - CAT I and CAT II
python stig_to_markdown.py U_RHEL_8_STIG.zip -s high medium
python stig_to_markdown.py U_RHEL_8_STIG.zip --severity cat1 cat2

# Combine with output directory
python stig_to_markdown.py U_RHEL_8_STIG.zip ./output -s high
```

**Severity Level Options:**

| Input Options | Severity Level |
|---------------|----------------|
| `high`, `cat1`, `cati`, `1`, `i` | CAT I (High) |
| `medium`, `cat2`, `catii`, `2`, `ii` | CAT II (Medium) |
| `low`, `cat3`, `catiii`, `3`, `iii` | CAT III (Low) |

When filtering, the output filename will include the severity suffix (e.g., `U_RHEL_8_STIG_CAT1.md`).

### Command Line Help

```bash
python stig_to_markdown.py --help
```

### Example Output

The script generates a Markdown file with the following structure:

```markdown
# Windows Server 2019 Security Technical Implementation Guide

> Description of the STIG...

## Benchmark Information

| Property | Value |
|----------|-------|
| Version | 2 |
| Release | Release 1 |
| Total Rules | 273 |
| CAT I (High) | 25 |
| CAT II (Medium) | 200 |
| CAT III (Low) | 48 |

## Table of Contents

| STIG ID | Severity | Title |
|---------|----------|-------|
| [V-205625](#v-205625) | CAT I | Windows Server 2019 must use... |
...

## STIG Rules

### V-205625

**Windows Server 2019 must use an anti-virus program.**

- **Severity:** 🔴 **CAT I (High)**
- **Rule ID:** `SV-205625r569188_rule`
- **CCI:** CCI-000366

#### Vulnerability Discussion

Malicious software can establish...

#### Check Procedure

\`\`\`
Verify an anti-virus solution is installed...
\`\`\`

#### Fix Procedure

\`\`\`
Install an anti-virus solution on the system.
\`\`\`
```

## Supported STIG Formats

This tool supports DISA STIG zip files containing XCCDF 1.1 or 1.2 formatted XML files. These are the standard format distributed by DISA through:

- [DISA STIG Library](https://public.cyber.mil/stigs/)
- [DISA IASE](https://www.stigviewer.com/)

## Programmatic Usage

You can also use the module programmatically:

```python
from stig_to_markdown import process_stig, parse_xccdf, convert_to_markdown
from pathlib import Path

# Process a complete STIG zip
output_file = process_stig('/path/to/stig.zip', '/output/dir')

# Or parse an XCCDF file directly
benchmark = parse_xccdf(Path('/path/to/xccdf.xml'))
markdown = convert_to_markdown(benchmark)
```

## Error Handling

The script handles common issues gracefully:

- Missing or invalid zip files
- XCCDF file not found in archive
- Malformed XML content
- Missing rule elements

Errors are reported clearly with actionable messages.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run linting: `pylint stig_to_markdown.py`
5. Submit a pull request

## License

MIT License - Feel free to use and modify as needed.

## Troubleshooting

### "Could not find XCCDF file"

The STIG zip may have a non-standard structure. Ensure the zip contains an XML file with "xccdf" in the filename.

### XML Parsing Errors

Some older STIGs may have encoding issues. Ensure the zip file was downloaded correctly and isn't corrupted.

### Missing Rule Content

Some STIG rules may have minimal content. The script will display "No description available" for empty fields.

