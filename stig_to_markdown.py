#!/usr/bin/env python3
"""
DISA STIG XCCDF to Markdown Converter

This script extracts DISA STIG zip files and converts the XCCDF XML content
into readable Markdown documentation.

Usage:
    python stig_to_markdown.py <stig_zip_file> [output_directory]
    python stig_to_markdown.py <stig_zip_file> -s high medium
    python stig_to_markdown.py <stig_zip_file> --severity cat1
"""

import argparse
import os
import sys
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional, List, Set
from dataclasses import dataclass, field


# XCCDF namespace mappings commonly found in DISA STIGs
NAMESPACES = {
    'xccdf': 'http://checklists.nist.gov/xccdf/1.1',
    'xccdf-1.2': 'http://checklists.nist.gov/xccdf/1.2',
    'dc': 'http://purl.org/dc/elements/1.1/',
    'cpe': 'http://cpe.mitre.org/language/2.0',
}

# Severity level mappings (normalize various input formats)
SEVERITY_ALIASES = {
    'high': 'high',
    'cat1': 'high',
    'cati': 'high',
    'cat-1': 'high',
    'cat-i': 'high',
    '1': 'high',
    'i': 'high',
    'medium': 'medium',
    'cat2': 'medium',
    'catii': 'medium',
    'cat-2': 'medium',
    'cat-ii': 'medium',
    '2': 'medium',
    'ii': 'medium',
    'low': 'low',
    'cat3': 'low',
    'catiii': 'low',
    'cat-3': 'low',
    'cat-iii': 'low',
    '3': 'low',
    'iii': 'low',
}

# Valid severity choices for argparse help text
SEVERITY_CHOICES = ['high', 'medium', 'low', 'cat1', 'cat2', 'cat3', '1', '2', '3']


def normalize_severity(severity_input: str) -> Optional[str]:
    """
    Normalize a severity input to standard format (high/medium/low).
    
    Args:
        severity_input: User-provided severity string
        
    Returns:
        Normalized severity or None if invalid
    """
    return SEVERITY_ALIASES.get(severity_input.lower().strip())


def normalize_severity_list(severities: List[str]) -> Set[str]:
    """
    Normalize a list of severity inputs to a set of standard values.
    
    Args:
        severities: List of user-provided severity strings
        
    Returns:
        Set of normalized severity values (high, medium, low)
    """
    normalized = set()
    for sev in severities:
        norm = normalize_severity(sev)
        if norm:
            normalized.add(norm)
        else:
            print(f"Warning: Unknown severity '{sev}', ignoring.")
    return normalized


def filter_rules_by_severity(rules: List, severities: Set[str]) -> List:
    """
    Filter rules to only include specified severity levels.
    
    Args:
        rules: List of StigRule objects
        severities: Set of severity levels to include (high, medium, low)
        
    Returns:
        Filtered list of rules
    """
    if not severities:
        return rules
    return [r for r in rules if r.severity.lower() in severities]


def get_severity_suffix(severities: Set[str]) -> str:
    """
    Generate a filename suffix based on filtered severities.
    
    Args:
        severities: Set of severity levels
        
    Returns:
        String suffix for filename
    """
    if not severities or len(severities) == 3:
        return ""
    
    cat_map = {'high': 'CAT1', 'medium': 'CAT2', 'low': 'CAT3'}
    cats = sorted([cat_map[s] for s in severities])
    return f"_{'_'.join(cats)}"


@dataclass
class StigRule:
    """Represents a single STIG rule/finding."""
    rule_id: str
    stig_id: str
    severity: str
    title: str
    description: str
    check_text: str
    fix_text: str
    cci_refs: list = field(default_factory=list)
    legacy_ids: list = field(default_factory=list)


@dataclass
class StigBenchmark:
    """Represents a STIG benchmark document."""
    title: str
    description: str
    version: str
    release_info: str
    rules: list = field(default_factory=list)


def find_xccdf_file(extract_dir: Path) -> Optional[Path]:
    """
    Find the XCCDF XML file within the extracted STIG directory.
    
    Args:
        extract_dir: Path to the extracted STIG contents
        
    Returns:
        Path to the XCCDF file or None if not found
    """
    # DISA STIGs typically have xccdf in the filename
    for xml_file in extract_dir.rglob('*xccdf*.xml'):
        # Skip manual XCCDF files, prefer automated
        if 'manual' not in xml_file.name.lower():
            return xml_file
    
    # Fall back to any xccdf file
    for xml_file in extract_dir.rglob('*xccdf*.xml'):
        return xml_file
    
    # Last resort: look for any XML file with Benchmark root
    for xml_file in extract_dir.rglob('*.xml'):
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            if 'Benchmark' in root.tag:
                return xml_file
        except ET.ParseError:
            continue
    
    return None


def extract_stig_zip(zip_path: Path, extract_dir: Path) -> Path:
    """
    Extract a STIG zip file to the specified directory.
    
    Args:
        zip_path: Path to the STIG zip file
        extract_dir: Directory to extract contents to
        
    Returns:
        Path to the extraction directory
    """
    extract_dir.mkdir(parents=True, exist_ok=True)
    
    with zipfile.ZipFile(zip_path, 'r') as zip_ref:
        zip_ref.extractall(extract_dir)
    
    print(f"Extracted STIG to: {extract_dir}")
    return extract_dir


def get_text_content(element: Optional[ET.Element], default: str = "") -> str:
    """
    Safely extract text content from an XML element.
    
    Args:
        element: XML element to extract text from
        default: Default value if element is None or has no text
        
    Returns:
        Text content of the element
    """
    if element is None:
        return default
    
    # Handle elements with mixed content (text + child elements)
    text_parts = []
    if element.text:
        text_parts.append(element.text.strip())
    
    for child in element:
        if child.tail:
            text_parts.append(child.tail.strip())
        # Recursively get text from children
        child_text = get_text_content(child)
        if child_text:
            text_parts.append(child_text)
    
    return ' '.join(text_parts) if text_parts else default


def detect_namespace(root: ET.Element) -> str:
    """
    Detect the XCCDF namespace version from the root element.
    
    Args:
        root: Root XML element
        
    Returns:
        The detected namespace URI
    """
    tag = root.tag
    if '{' in tag:
        ns = tag[1:tag.index('}')]
        return ns
    return NAMESPACES['xccdf']


def parse_xccdf(xccdf_path: Path) -> StigBenchmark:
    """
    Parse an XCCDF XML file into a StigBenchmark object.
    
    Args:
        xccdf_path: Path to the XCCDF XML file
        
    Returns:
        StigBenchmark object containing parsed data
    """
    tree = ET.parse(xccdf_path)
    root = tree.getroot()
    
    # Detect namespace
    ns = detect_namespace(root)
    ns_map = {'xccdf': ns}
    
    # Extract benchmark metadata
    title_elem = root.find('.//xccdf:title', ns_map)
    title = get_text_content(title_elem, "Unknown STIG")
    
    desc_elem = root.find('.//xccdf:description', ns_map)
    description = get_text_content(desc_elem, "")
    
    version_elem = root.find('.//xccdf:version', ns_map)
    version = get_text_content(version_elem, "Unknown")
    
    # Try to get release info from plain-text element
    release_elem = root.find('.//xccdf:plain-text[@id="release-info"]', ns_map)
    release_info = get_text_content(release_elem, "")
    
    benchmark = StigBenchmark(
        title=title,
        description=description,
        version=version,
        release_info=release_info
    )
    
    # Parse all rules
    for group in root.findall('.//xccdf:Group', ns_map):
        rule_elem = group.find('.//xccdf:Rule', ns_map)
        if rule_elem is None:
            continue
        
        rule = parse_rule(group, rule_elem, ns_map)
        if rule:
            benchmark.rules.append(rule)
    
    # Sort rules by STIG ID
    benchmark.rules.sort(key=lambda r: r.stig_id)
    
    return benchmark


def parse_rule(group: ET.Element, rule_elem: ET.Element, ns_map: dict) -> Optional[StigRule]:
    """
    Parse a single STIG rule from XML elements.
    
    Args:
        group: The Group element containing the rule
        rule_elem: The Rule element
        ns_map: Namespace mapping dictionary
        
    Returns:
        StigRule object or None if parsing fails
    """
    try:
        # Get rule ID
        rule_id = rule_elem.get('id', 'Unknown')
        
        # Get STIG ID (V-number) from Group id
        stig_id = group.get('id', 'Unknown')
        
        # Get severity
        severity = rule_elem.get('severity', 'unknown')
        
        # Get title
        title_elem = rule_elem.find('xccdf:title', ns_map)
        title = get_text_content(title_elem, "No title")
        
        # Get description (often contains vuln discussion)
        desc_elem = rule_elem.find('xccdf:description', ns_map)
        description = get_text_content(desc_elem, "No description available")
        
        # Clean up description - often has embedded XML-like content
        description = clean_description(description)
        
        # Get check content
        check_elem = rule_elem.find('.//xccdf:check-content', ns_map)
        check_text = get_text_content(check_elem, "No check procedure available")
        
        # Get fix text
        fix_elem = rule_elem.find('.//xccdf:fixtext', ns_map)
        fix_text = get_text_content(fix_elem, "No fix text available")
        
        # Get CCI references
        cci_refs = []
        for ident in rule_elem.findall('.//xccdf:ident', ns_map):
            if ident.text and ident.text.startswith('CCI-'):
                cci_refs.append(ident.text)
        
        # Get legacy IDs
        legacy_ids = []
        for ident in rule_elem.findall('.//xccdf:ident', ns_map):
            if ident.text and (ident.text.startswith('SV-') or ident.text.startswith('V-')):
                legacy_ids.append(ident.text)
        
        return StigRule(
            rule_id=rule_id,
            stig_id=stig_id,
            severity=severity,
            title=title,
            description=description,
            check_text=check_text,
            fix_text=fix_text,
            cci_refs=cci_refs,
            legacy_ids=legacy_ids
        )
    except Exception as e:
        print(f"Warning: Failed to parse rule: {e}")
        return None


def clean_description(description: str) -> str:
    """
    Clean up STIG description text by removing embedded markup.
    
    Args:
        description: Raw description text
        
    Returns:
        Cleaned description text
    """
    import re
    
    # Remove VulnDiscussion tags but keep content
    description = re.sub(r'<VulnDiscussion>(.*?)</VulnDiscussion>', r'\1', description, flags=re.DOTALL)
    
    # Remove other common embedded tags
    description = re.sub(r'<FalsePositives>.*?</FalsePositives>', '', description, flags=re.DOTALL)
    description = re.sub(r'<FalseNegatives>.*?</FalseNegatives>', '', description, flags=re.DOTALL)
    description = re.sub(r'<Documentable>.*?</Documentable>', '', description, flags=re.DOTALL)
    description = re.sub(r'<Mitigations>.*?</Mitigations>', '', description, flags=re.DOTALL)
    description = re.sub(r'<SeverityOverrideGuidance>.*?</SeverityOverrideGuidance>', '', description, flags=re.DOTALL)
    description = re.sub(r'<PotentialImpacts>.*?</PotentialImpacts>', '', description, flags=re.DOTALL)
    description = re.sub(r'<ThirdPartyTools>.*?</ThirdPartyTools>', '', description, flags=re.DOTALL)
    description = re.sub(r'<MitigationControl>.*?</MitigationControl>', '', description, flags=re.DOTALL)
    description = re.sub(r'<Responsibility>.*?</Responsibility>', '', description, flags=re.DOTALL)
    description = re.sub(r'<IAControls>.*?</IAControls>', '', description, flags=re.DOTALL)
    
    # Clean up whitespace
    description = ' '.join(description.split())
    
    return description.strip()


def severity_badge(severity: str) -> str:
    """
    Convert severity to a readable badge/label.
    
    Args:
        severity: Severity level (high, medium, low)
        
    Returns:
        Formatted severity badge
    """
    severity_map = {
        'high': '🔴 **CAT I (High)**',
        'medium': '🟠 **CAT II (Medium)**',
        'low': '🟡 **CAT III (Low)**',
    }
    return severity_map.get(severity.lower(), f'⚪ **{severity}**')


def convert_to_markdown(benchmark: StigBenchmark, severity_filter: Optional[Set[str]] = None) -> str:
    """
    Convert a StigBenchmark to Markdown format.
    
    Args:
        benchmark: StigBenchmark object to convert
        severity_filter: Optional set of severity levels to include
        
    Returns:
        Markdown formatted string
    """
    # Apply severity filter if provided
    rules = filter_rules_by_severity(benchmark.rules, severity_filter) if severity_filter else benchmark.rules
    
    lines = []
    
    # Document header
    lines.append(f"# {benchmark.title}")
    lines.append("")
    
    if benchmark.description:
        lines.append(f"> {benchmark.description}")
        lines.append("")
    
    # Show filter notice if applicable
    if severity_filter and len(severity_filter) < 3:
        cat_names = {'high': 'CAT I (High)', 'medium': 'CAT II (Medium)', 'low': 'CAT III (Low)'}
        filtered_cats = ', '.join([cat_names[s] for s in sorted(severity_filter)])
        lines.append(f"**🔍 Filtered by severity:** {filtered_cats}")
        lines.append("")
    
    # Metadata table
    lines.append("## Benchmark Information")
    lines.append("")
    lines.append("| Property | Value |")
    lines.append("|----------|-------|")
    lines.append(f"| Version | {benchmark.version} |")
    if benchmark.release_info:
        lines.append(f"| Release | {benchmark.release_info} |")
    
    # Count by severity (from filtered rules)
    high_count = sum(1 for r in rules if r.severity.lower() == 'high')
    medium_count = sum(1 for r in rules if r.severity.lower() == 'medium')
    low_count = sum(1 for r in rules if r.severity.lower() == 'low')
    
    # Show total from original if filtered
    if severity_filter and len(severity_filter) < 3:
        lines.append(f"| Total Rules (filtered) | {len(rules)} of {len(benchmark.rules)} |")
    else:
        lines.append(f"| Total Rules | {len(rules)} |")
    
    lines.append(f"| CAT I (High) | {high_count} |")
    lines.append(f"| CAT II (Medium) | {medium_count} |")
    lines.append(f"| CAT III (Low) | {low_count} |")
    lines.append("")
    
    # Table of Contents
    lines.append("## Table of Contents")
    lines.append("")
    lines.append("| STIG ID | Severity | Title |")
    lines.append("|---------|----------|-------|")
    
    for rule in rules:
        severity_short = {'high': 'CAT I', 'medium': 'CAT II', 'low': 'CAT III'}.get(
            rule.severity.lower(), rule.severity
        )
        # Create anchor link
        anchor = f"#{rule.stig_id.lower()}"
        lines.append(f"| [{rule.stig_id}]({anchor}) | {severity_short} | {rule.title[:60]}{'...' if len(rule.title) > 60 else ''} |")
    
    lines.append("")
    
    # Rules section
    lines.append("---")
    lines.append("")
    lines.append("## STIG Rules")
    lines.append("")
    
    for rule in rules:
        lines.extend(format_rule_markdown(rule))
        lines.append("")
    
    return '\n'.join(lines)


def format_rule_markdown(rule: StigRule) -> list:
    """
    Format a single STIG rule as Markdown.
    
    Args:
        rule: StigRule object to format
        
    Returns:
        List of Markdown lines
    """
    lines = []
    
    lines.append(f"### {rule.stig_id}")
    lines.append("")
    lines.append(f"**{rule.title}**")
    lines.append("")
    lines.append(f"- **Severity:** {severity_badge(rule.severity)}")
    lines.append(f"- **Rule ID:** `{rule.rule_id}`")
    
    if rule.cci_refs:
        lines.append(f"- **CCI:** {', '.join(rule.cci_refs)}")
    
    if rule.legacy_ids:
        lines.append(f"- **Legacy IDs:** {', '.join(rule.legacy_ids)}")
    
    lines.append("")
    
    # Description/Discussion
    lines.append("#### Vulnerability Discussion")
    lines.append("")
    lines.append(rule.description)
    lines.append("")
    
    # Check procedure
    lines.append("#### Check Procedure")
    lines.append("")
    lines.append("```")
    lines.append(rule.check_text)
    lines.append("```")
    lines.append("")
    
    # Fix procedure
    lines.append("#### Fix Procedure")
    lines.append("")
    lines.append("```")
    lines.append(rule.fix_text)
    lines.append("```")
    lines.append("")
    lines.append("---")
    
    return lines


def process_stig(
    zip_path: str,
    output_dir: Optional[str] = None,
    severity_filter: Optional[List[str]] = None
) -> Path:
    """
    Main processing function to convert a STIG zip to Markdown.
    
    Args:
        zip_path: Path to the STIG zip file
        output_dir: Optional output directory (defaults to current directory)
        severity_filter: Optional list of severity levels to include
        
    Returns:
        Path to the generated Markdown file
    """
    zip_path = Path(zip_path)
    
    if not zip_path.exists():
        raise FileNotFoundError(f"STIG zip file not found: {zip_path}")
    
    if not zipfile.is_zipfile(zip_path):
        raise ValueError(f"Not a valid zip file: {zip_path}")
    
    # Normalize severity filter
    normalized_severities = None
    if severity_filter:
        normalized_severities = normalize_severity_list(severity_filter)
        if normalized_severities:
            cat_names = {'high': 'CAT I', 'medium': 'CAT II', 'low': 'CAT III'}
            print(f"Filtering by severity: {', '.join([cat_names[s] for s in sorted(normalized_severities)])}")
    
    # Set up output directory
    if output_dir:
        output_path = Path(output_dir)
    else:
        output_path = Path.cwd()
    
    output_path.mkdir(parents=True, exist_ok=True)
    
    # Create extraction directory
    extract_dir = output_path / f"_extracted_{zip_path.stem}"
    
    try:
        # Extract the zip
        extract_stig_zip(zip_path, extract_dir)
        
        # Find the XCCDF file
        xccdf_file = find_xccdf_file(extract_dir)
        if not xccdf_file:
            raise FileNotFoundError("Could not find XCCDF file in the extracted contents")
        
        print(f"Found XCCDF file: {xccdf_file}")
        
        # Parse the XCCDF
        benchmark = parse_xccdf(xccdf_file)
        print(f"Parsed {len(benchmark.rules)} rules from {benchmark.title}")
        
        # Convert to Markdown with optional severity filter
        markdown_content = convert_to_markdown(benchmark, normalized_severities)
        
        # Generate output filename with severity suffix
        severity_suffix = get_severity_suffix(normalized_severities) if normalized_severities else ""
        output_filename = f"{zip_path.stem}_STIG{severity_suffix}.md"
        output_file = output_path / output_filename
        
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(markdown_content)
        
        # Print filtered count
        if normalized_severities and len(normalized_severities) < 3:
            filtered_count = len(filter_rules_by_severity(benchmark.rules, normalized_severities))
            print(f"Filtered to {filtered_count} rules (from {len(benchmark.rules)} total)")
        
        print(f"Generated Markdown: {output_file}")
        return output_file
        
    finally:
        # Clean up extracted files
        import shutil
        if extract_dir.exists():
            shutil.rmtree(extract_dir)
            print(f"Cleaned up extraction directory")


def load_stig(zip_path: str) -> StigBenchmark:
    """
    Load and parse a STIG zip file without converting.
    
    Args:
        zip_path: Path to the STIG zip file
        
    Returns:
        StigBenchmark object containing parsed data
    """
    import shutil
    import tempfile
    
    zip_path = Path(zip_path)
    
    if not zip_path.exists():
        raise FileNotFoundError(f"STIG zip file not found: {zip_path}")
    
    if not zipfile.is_zipfile(zip_path):
        raise ValueError(f"Not a valid zip file: {zip_path}")
    
    # Create temporary extraction directory
    extract_dir = Path(tempfile.mkdtemp(prefix="stig_"))
    
    try:
        # Extract the zip
        with zipfile.ZipFile(zip_path, 'r') as zip_ref:
            zip_ref.extractall(extract_dir)
        
        # Find the XCCDF file
        xccdf_file = find_xccdf_file(extract_dir)
        if not xccdf_file:
            raise FileNotFoundError("Could not find XCCDF file in the extracted contents")
        
        # Parse and return the benchmark
        return parse_xccdf(xccdf_file)
        
    finally:
        # Clean up extracted files
        if extract_dir.exists():
            shutil.rmtree(extract_dir)


def search_rules(benchmark: StigBenchmark, query: str, severity_filter: Optional[Set[str]] = None) -> List[StigRule]:
    """
    Search rules by query string.
    
    Args:
        benchmark: StigBenchmark to search
        query: Search query (searches ID, title, description, rule_id, CCI refs)
        severity_filter: Optional set of severity levels to include
        
    Returns:
        List of matching StigRule objects
    """
    query_lower = query.lower().strip()
    matching_rules = []
    
    # Apply severity filter first if provided
    rules = filter_rules_by_severity(benchmark.rules, severity_filter) if severity_filter else benchmark.rules
    
    for rule in rules:
        if (
            query_lower in rule.stig_id.lower() or
            query_lower in rule.title.lower() or
            query_lower in rule.description.lower() or
            query_lower in rule.rule_id.lower() or
            query_lower in rule.check_text.lower() or
            query_lower in rule.fix_text.lower() or
            any(query_lower in cci.lower() for cci in rule.cci_refs)
        ):
            matching_rules.append(rule)
    
    return matching_rules


def format_rule_list(rules: List[StigRule], show_title: bool = True) -> str:
    """
    Format a list of rules for console output.
    
    Args:
        rules: List of StigRule objects
        show_title: Whether to show the title column
        
    Returns:
        Formatted string for console output
    """
    if not rules:
        return "No rules found."
    
    severity_display = {
        'high': 'CAT I  ',
        'medium': 'CAT II ',
        'low': 'CAT III',
    }
    
    lines = []
    lines.append("")
    
    if show_title:
        lines.append(f"{'STIG ID':<12} {'Severity':<9} Title")
        lines.append("-" * 80)
        
        for rule in rules:
            sev = severity_display.get(rule.severity.lower(), rule.severity[:7])
            title = rule.title[:55] + "..." if len(rule.title) > 55 else rule.title
            lines.append(f"{rule.stig_id:<12} {sev:<9} {title}")
    else:
        lines.append(f"{'STIG ID':<12} {'Severity':<9}")
        lines.append("-" * 25)
        
        for rule in rules:
            sev = severity_display.get(rule.severity.lower(), rule.severity[:7])
            lines.append(f"{rule.stig_id:<12} {sev}")
    
    lines.append("")
    lines.append(f"Total: {len(rules)} rule(s)")
    
    return '\n'.join(lines)


def format_rule_detail(rule: StigRule) -> str:
    """
    Format a single rule for detailed console output.
    
    Args:
        rule: StigRule object to format
        
    Returns:
        Formatted string for console output
    """
    severity_display = {
        'high': 'CAT I (High)',
        'medium': 'CAT II (Medium)',
        'low': 'CAT III (Low)',
    }
    
    lines = []
    lines.append("")
    lines.append("=" * 80)
    lines.append(f"  {rule.stig_id}")
    lines.append("=" * 80)
    lines.append("")
    lines.append(f"Title:    {rule.title}")
    lines.append(f"Severity: {severity_display.get(rule.severity.lower(), rule.severity)}")
    lines.append(f"Rule ID:  {rule.rule_id}")
    
    if rule.cci_refs:
        lines.append(f"CCI:      {', '.join(rule.cci_refs)}")
    
    if rule.legacy_ids:
        lines.append(f"Legacy:   {', '.join(rule.legacy_ids)}")
    
    lines.append("")
    lines.append("-" * 40)
    lines.append("VULNERABILITY DISCUSSION")
    lines.append("-" * 40)
    lines.append("")
    lines.append(rule.description)
    
    lines.append("")
    lines.append("-" * 40)
    lines.append("CHECK PROCEDURE")
    lines.append("-" * 40)
    lines.append("")
    lines.append(rule.check_text)
    
    lines.append("")
    lines.append("-" * 40)
    lines.append("FIX PROCEDURE")
    lines.append("-" * 40)
    lines.append("")
    lines.append(rule.fix_text)
    
    lines.append("")
    lines.append("=" * 80)
    
    return '\n'.join(lines)


def get_stig_short_name(benchmark: StigBenchmark) -> str:
    """
    Extract a short name from the STIG title for display.
    
    Args:
        benchmark: StigBenchmark object
        
    Returns:
        Short name string (e.g., "RHEL 9", "Windows 2022")
    """
    title = benchmark.title
    # Try to extract OS name from common patterns
    if 'Red Hat Enterprise Linux' in title:
        import re
        match = re.search(r'Red Hat Enterprise Linux (\d+)', title)
        if match:
            return f"RHEL {match.group(1)}"
    elif 'Windows Server' in title:
        import re
        match = re.search(r'Windows Server (\d+)', title)
        if match:
            return f"Win {match.group(1)}"
    elif 'Windows' in title:
        import re
        match = re.search(r'Windows (\d+)', title)
        if match:
            return f"Win {match.group(1)}"
    elif 'Ubuntu' in title:
        import re
        match = re.search(r'Ubuntu (\d+\.\d+)', title)
        if match:
            return f"Ubuntu {match.group(1)}"
    
    # Fallback: first 15 chars
    return title[:15] + "..." if len(title) > 15 else title


def format_multi_stig_list(loaded_stigs: List[tuple], severity_filter: Optional[Set[str]] = None) -> str:
    """
    Format rules from multiple STIGs for console output.
    
    Args:
        loaded_stigs: List of (short_name, benchmark) tuples
        severity_filter: Optional set of severity levels to include
        
    Returns:
        Formatted string for console output
    """
    severity_display = {
        'high': 'CAT I  ',
        'medium': 'CAT II ',
        'low': 'CAT III',
    }
    
    lines = []
    total_rules = 0
    
    for short_name, benchmark in loaded_stigs:
        rules = filter_rules_by_severity(benchmark.rules, severity_filter) if severity_filter else benchmark.rules
        
        if not rules:
            continue
        
        lines.append("")
        lines.append(f"{'=' * 80}")
        lines.append(f"  {benchmark.title}")
        lines.append(f"{'=' * 80}")
        lines.append("")
        lines.append(f"{'STIG ID':<12} {'Severity':<9} Title")
        lines.append("-" * 80)
        
        for rule in rules:
            sev = severity_display.get(rule.severity.lower(), rule.severity[:7])
            title = rule.title[:55] + "..." if len(rule.title) > 55 else rule.title
            lines.append(f"{rule.stig_id:<12} {sev:<9} {title}")
        
        lines.append("")
        lines.append(f"Subtotal: {len(rules)} rule(s)")
        total_rules += len(rules)
    
    lines.append("")
    lines.append("=" * 80)
    lines.append(f"Total: {total_rules} rule(s) across {len(loaded_stigs)} STIG(s)")
    
    return '\n'.join(lines)


def format_multi_stig_search(loaded_stigs: List[tuple], query: str, severity_filter: Optional[Set[str]] = None) -> str:
    """
    Format search results from multiple STIGs for console output.
    
    Args:
        loaded_stigs: List of (short_name, benchmark) tuples
        query: Search query string
        severity_filter: Optional set of severity levels to include
        
    Returns:
        Formatted string for console output
    """
    severity_display = {
        'high': 'CAT I  ',
        'medium': 'CAT II ',
        'low': 'CAT III',
    }
    
    lines = []
    total_matches = 0
    
    for short_name, benchmark in loaded_stigs:
        matches = search_rules(benchmark, query, severity_filter)
        
        if not matches:
            continue
        
        lines.append("")
        lines.append(f"{'=' * 80}")
        lines.append(f"  {benchmark.title}")
        lines.append(f"{'=' * 80}")
        lines.append("")
        lines.append(f"{'STIG ID':<12} {'Severity':<9} Title")
        lines.append("-" * 80)
        
        for rule in matches:
            sev = severity_display.get(rule.severity.lower(), rule.severity[:7])
            title = rule.title[:55] + "..." if len(rule.title) > 55 else rule.title
            lines.append(f"{rule.stig_id:<12} {sev:<9} {title}")
        
        lines.append("")
        lines.append(f"Matches: {len(matches)}")
        total_matches += len(matches)
    
    if total_matches == 0:
        return "\nNo matches found."
    
    lines.append("")
    lines.append("=" * 80)
    lines.append(f"Total: {total_matches} match(es) across {len(loaded_stigs)} STIG(s)")
    
    return '\n'.join(lines)


def main():
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        description='Convert DISA STIG XCCDF files to Markdown documentation',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
    # Launch interactive TUI mode
    python stig_to_markdown.py --tui
    
    # Use STIGs from default ./stigs/ directory
    python stig_to_markdown.py --list
    python stig_to_markdown.py -q "password"
    python stig_to_markdown.py -o ./output
    
    # Or specify STIG file(s) explicitly
    python stig_to_markdown.py U_RHEL_8_STIG.zip
    python stig_to_markdown.py U_RHEL_9_STIG.zip U_Windows_STIG.zip -o ./output
    
    # Filter by severity
    python stig_to_markdown.py -s high
    python stig_to_markdown.py -s cat1 cat2
    
    # List rules
    python stig_to_markdown.py --list
    python stig_to_markdown.py -l -s high
    
    # Search STIGs
    python stig_to_markdown.py --search "ssh"
    python stig_to_markdown.py -q "password" -s high
    
    # Get details for a specific STIG rule
    python stig_to_markdown.py --info V-257984
    
Default directory: ./stigs/ (place STIG zip files here for auto-discovery)

Severity options:
    high, cat1, 1    - CAT I (High severity)
    medium, cat2, 2  - CAT II (Medium severity)  
    low, cat3, 3     - CAT III (Low severity)
        """
    )
    
    parser.add_argument(
        'stig_files',
        nargs='*',
        metavar='STIG_ZIP',
        help='Path(s) to DISA STIG zip file(s) - if not specified, uses ./stigs/ directory'
    )
    
    parser.add_argument(
        '-o', '--output',
        metavar='DIR',
        default=None,
        help='Output directory for Markdown file(s) (default: current directory)'
    )
    
    parser.add_argument(
        '-s', '--severity',
        nargs='+',
        metavar='LEVEL',
        help='Filter by severity level(s): high/cat1/1, medium/cat2/2, low/cat3/3'
    )
    
    parser.add_argument(
        '-l', '--list',
        action='store_true',
        help='List all STIG rules (can combine with -s to filter by severity)'
    )
    
    parser.add_argument(
        '-q', '--search',
        metavar='QUERY',
        help='Search STIGs by ID, title, description, or CCI reference'
    )
    
    parser.add_argument(
        '-i', '--info',
        metavar='STIG_ID',
        help='Show detailed information for a specific STIG ID (e.g., V-257984)'
    )
    
    parser.add_argument(
        '--tui',
        action='store_true',
        help='Launch interactive Terminal User Interface mode (requires: pip install textual)'
    )
    
    args = parser.parse_args()
    
    # TUI mode
    if args.tui:
        try:
            from stig_tui import run_tui
            run_tui()
            sys.exit(0)
        except ImportError as e:
            print("❌ TUI mode requires the 'textual' package.", file=sys.stderr)
            print("   Install with: pip install textual", file=sys.stderr)
            print(f"\n   Error: {e}", file=sys.stderr)
            sys.exit(1)
    
    # Default STIG directory
    DEFAULT_STIG_DIR = Path("./stigs")
    
    # If no files specified, check default directory
    stig_files = args.stig_files
    if not stig_files:
        if DEFAULT_STIG_DIR.exists() and DEFAULT_STIG_DIR.is_dir():
            # Find all zip files in the default directory
            stig_files = sorted([str(f) for f in DEFAULT_STIG_DIR.glob("*.zip")])
            if stig_files:
                print(f"Using STIG files from default directory: {DEFAULT_STIG_DIR}/")
            else:
                print(f"No .zip files found in {DEFAULT_STIG_DIR}/", file=sys.stderr)
                parser.print_help()
                print("\n❌ Error: No STIG files specified and none found in ./stigs/", file=sys.stderr)
                sys.exit(1)
        else:
            parser.print_help()
            print("\n❌ Error: At least one STIG zip file is required (or use --tui for interactive mode)", file=sys.stderr)
            print(f"   Tip: Place STIG zip files in {DEFAULT_STIG_DIR}/ to use them by default.", file=sys.stderr)
            sys.exit(1)
    
    # Normalize severity filter if provided
    severity_filter = None
    if args.severity:
        severity_filter = normalize_severity_list(args.severity)
    
    try:
        # Load all STIG files
        loaded_stigs = []
        print(f"Loading {len(stig_files)} STIG file(s)...")
        for stig_path in stig_files:
            try:
                benchmark = load_stig(stig_path)
                short_name = get_stig_short_name(benchmark)
                loaded_stigs.append((short_name, benchmark, stig_path))
                print(f"  ✓ {short_name}: {benchmark.title} ({len(benchmark.rules)} rules)")
            except Exception as e:
                print(f"  ✗ {stig_path}: {e}", file=sys.stderr)
        
        if not loaded_stigs:
            print("\n❌ Error: No valid STIG files could be loaded.", file=sys.stderr)
            sys.exit(1)
        
        print("")
        
        # Info mode - show details for a specific STIG
        if args.info:
            search_id = args.info.upper()
            found_rule = None
            found_stig = None
            
            # Search across all loaded STIGs
            for short_name, benchmark, _ in loaded_stigs:
                for r in benchmark.rules:
                    if r.stig_id.upper() == search_id:
                        found_rule = r
                        found_stig = benchmark.title
                        break
                if found_rule:
                    break
            
            if found_rule:
                print(f"Found in: {found_stig}")
                print(format_rule_detail(found_rule))
            else:
                print(f"\n❌ STIG ID '{args.info}' not found in any loaded STIG.", file=sys.stderr)
                print(f"   Use --list to see available STIG IDs.", file=sys.stderr)
                sys.exit(1)
            sys.exit(0)
        
        # Search mode
        if args.search:
            print(f"Searching for: '{args.search}'")
            
            if severity_filter:
                cat_names = {'high': 'CAT I', 'medium': 'CAT II', 'low': 'CAT III'}
                print(f"Filtering by: {', '.join([cat_names[s] for s in sorted(severity_filter)])}")
            
            # Convert to format expected by format function
            stigs_for_search = [(name, bench) for name, bench, _ in loaded_stigs]
            print(format_multi_stig_search(stigs_for_search, args.search, severity_filter))
            
            print("\nTip: Use --info <STIG_ID> to see full details for a rule.")
            sys.exit(0)
        
        # List mode
        if args.list:
            if severity_filter:
                cat_names = {'high': 'CAT I', 'medium': 'CAT II', 'low': 'CAT III'}
                print(f"Filtering by: {', '.join([cat_names[s] for s in sorted(severity_filter)])}")
            
            # Convert to format expected by format function
            stigs_for_list = [(name, bench) for name, bench, _ in loaded_stigs]
            print(format_multi_stig_list(stigs_for_list, severity_filter))
            sys.exit(0)
        
        # Default: Convert to Markdown
        output_files = []
        for short_name, benchmark, stig_path in loaded_stigs:
            output_file = process_stig(
                stig_path,
                args.output,
                args.severity
            )
            output_files.append(output_file)
        
        print(f"\n✅ Successfully converted {len(output_files)} STIG(s) to Markdown:")
        for f in output_files:
            print(f"   - {f}")
        sys.exit(0)
        
    except Exception as e:
        print(f"\n❌ Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main()

