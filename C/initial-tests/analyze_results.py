#!/usr/bin/env python3
"""
Severity Mapper and Results Analyzer
Converts tool-specific severities to unified levels and analyzes results
"""

import json
import xml.etree.ElementTree as ET
from pathlib import Path
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List, Optional
import argparse


@dataclass
class Finding:
    """Represents a security finding"""
    tool: str
    file: str
    line: int
    rule_id: str
    message: str
    original_severity: str
    unified_severity: str
    cwe: Optional[str] = None


class SeverityMapper:
    """Maps tool-specific severities to unified levels"""
    
    # Unified severity levels (in order of priority)
    SEVERITY_ORDER = ['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
    
    # CWE-based severity overrides
    CWE_SEVERITY = {
        # Critical CWEs
        'CWE-78': 'CRITICAL',   # OS Command Injection
        'CWE-89': 'CRITICAL',   # SQL Injection
        'CWE-120': 'CRITICAL',  # Buffer Overflow
        'CWE-416': 'CRITICAL',  # Use After Free
        'CWE-787': 'CRITICAL',  # Out-of-bounds Write
        'CWE-22': 'CRITICAL',   # Path Traversal
        
        # High CWEs
        'CWE-119': 'HIGH',      # Buffer Errors
        'CWE-190': 'HIGH',      # Integer Overflow
        'CWE-476': 'HIGH',      # NULL Pointer Dereference
        'CWE-134': 'HIGH',      # Format String
        'CWE-131': 'HIGH',      # Incorrect Buffer Size Calculation
        'CWE-415': 'HIGH',      # Double Free
        
        # Medium CWEs
        'CWE-252': 'MEDIUM',    # Unchecked Return Value
        'CWE-401': 'MEDIUM',    # Memory Leak
        'CWE-457': 'MEDIUM',    # Use of Uninitialized Variable
        'CWE-563': 'MEDIUM',    # Unused Variable
    }
    
    @staticmethod
    def map_cppcheck(severity: str) -> str:
        """Map Cppcheck severity to unified level"""
        mapping = {
            'error': 'CRITICAL',
            'warning': 'MEDIUM',
            'style': 'LOW',
            'performance': 'LOW',
            'portability': 'LOW',
            'information': 'INFO'
        }
        return mapping.get(severity.lower(), 'INFO')
    
    @staticmethod
    def map_flawfinder(level: int) -> str:
        """Map Flawfinder risk level (0-5) to unified severity"""
        if level >= 5:
            return 'CRITICAL'
        elif level == 4:
            return 'HIGH'
        elif level == 3:
            return 'MEDIUM'
        elif level >= 1:
            return 'LOW'
        else:
            return 'INFO'
    
    @staticmethod
    def map_semgrep(severity: str, cwe: Optional[str] = None) -> str:
        """Map Semgrep severity to unified level"""
        base_mapping = {
            'ERROR': 'CRITICAL',
            'WARNING': 'MEDIUM',
            'INFO': 'LOW'
        }
        base_severity = base_mapping.get(severity.upper(), 'INFO')
        
        # Refine based on CWE if available
        if cwe:
            cwe_severity = SeverityMapper.CWE_SEVERITY.get(cwe)
            if cwe_severity:
                # Only upgrade, never downgrade
                if SeverityMapper.SEVERITY_ORDER.index(cwe_severity) > \
                   SeverityMapper.SEVERITY_ORDER.index(base_severity):
                    return cwe_severity
        
        return base_severity
    
    @classmethod
    def map_severity(cls, tool: str, original_severity: str, cwe: Optional[str] = None) -> str:
        """
        Unified severity mapper
        
        Args:
            tool: 'cppcheck', 'flawfinder', or 'semgrep'
            original_severity: original severity value from tool
            cwe: CWE identifier (optional, for refinement)
        
        Returns:
            Unified severity level
        """
        if tool == 'cppcheck':
            return cls.map_cppcheck(original_severity)
        elif tool == 'flawfinder':
            return cls.map_flawfinder(int(original_severity))
        elif tool == 'semgrep':
            return cls.map_semgrep(original_severity, cwe)
        else:
            return 'INFO'


class ResultsParser:
    """Parse tool outputs and extract findings"""
    
    @staticmethod
    def parse_cppcheck_xml(xml_file: Path) -> List[Finding]:
        """Parse Cppcheck XML output"""
        findings = []
        
        try:
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            for error in root.findall('.//error'):
                severity = error.get('severity', 'information')
                msg = error.get('msg', '')
                rule_id = error.get('id', 'unknown')
                
                # Extract CWE if available
                cwe = error.get('cwe')
                if cwe:
                    cwe = f"CWE-{cwe}"
                
                # Get location info
                location = error.find('location')
                if location is not None:
                    file_path = location.get('file', 'unknown')
                    line = int(location.get('line', '0'))
                else:
                    file_path = 'unknown'
                    line = 0
                
                unified_severity = SeverityMapper.map_severity('cppcheck', severity, cwe)
                
                findings.append(Finding(
                    tool='cppcheck',
                    file=file_path,
                    line=line,
                    rule_id=rule_id,
                    message=msg,
                    original_severity=severity,
                    unified_severity=unified_severity,
                    cwe=cwe
                ))
        
        except Exception as e:
            print(f"Error parsing Cppcheck XML: {e}")
        
        return findings
    
    @staticmethod
    def parse_flawfinder_sarif(sarif_file: Path) -> List[Finding]:
        """Parse Flawfinder SARIF output"""
        findings = []
        
        try:
            with open(sarif_file, 'r') as f:
                data = json.load(f)
            
            for run in data.get('runs', []):
                for result in run.get('results', []):
                    rule_id = result.get('ruleId', 'unknown')
                    message = result.get('message', {}).get('text', '')
                    
                    # Extract level (0-5)
                    level = result.get('properties', {}).get('level', 1)
                    
                    # Get location
                    locations = result.get('locations', [])
                    if locations:
                        loc = locations[0].get('physicalLocation', {})
                        file_path = loc.get('artifactLocation', {}).get('uri', 'unknown')
                        line = loc.get('region', {}).get('startLine', 0)
                    else:
                        file_path = 'unknown'
                        line = 0
                    
                    # Extract CWE from rule metadata
                    cwe = result.get('properties', {}).get('cwe')
                    if cwe and not cwe.startswith('CWE-'):
                        cwe = f"CWE-{cwe}"
                    
                    unified_severity = SeverityMapper.map_severity('flawfinder', str(level), cwe)
                    
                    findings.append(Finding(
                        tool='flawfinder',
                        file=file_path,
                        line=line,
                        rule_id=rule_id,
                        message=message,
                        original_severity=str(level),
                        unified_severity=unified_severity,
                        cwe=cwe
                    ))
        
        except Exception as e:
            print(f"Error parsing Flawfinder SARIF: {e}")
        
        return findings
    
    @staticmethod
    def parse_semgrep_sarif(sarif_file: Path) -> List[Finding]:
        """Parse Semgrep SARIF output"""
        findings = []
        
        try:
            with open(sarif_file, 'r') as f:
                data = json.load(f)
            
            for run in data.get('runs', []):
                for result in run.get('results', []):
                    rule_id = result.get('ruleId', 'unknown')
                    message = result.get('message', {}).get('text', '')
                    level = result.get('level', 'note')  # error, warning, note
                    
                    # Map SARIF level to Semgrep severity
                    severity_map = {'error': 'ERROR', 'warning': 'WARNING', 'note': 'INFO'}
                    severity = severity_map.get(level, 'INFO')
                    
                    # Get location
                    locations = result.get('locations', [])
                    if locations:
                        loc = locations[0].get('physicalLocation', {})
                        file_path = loc.get('artifactLocation', {}).get('uri', 'unknown')
                        line = loc.get('region', {}).get('startLine', 0)
                    else:
                        file_path = 'unknown'
                        line = 0
                    
                    # Extract CWE from properties or metadata
                    cwe = None
                    props = result.get('properties', {})
                    if 'cwe' in props:
                        cwe = props['cwe']
                    elif 'tags' in props:
                        for tag in props['tags']:
                            if tag.startswith('CWE-'):
                                cwe = tag
                                break
                    
                    unified_severity = SeverityMapper.map_severity('semgrep', severity, cwe)
                    
                    findings.append(Finding(
                        tool='semgrep',
                        file=file_path,
                        line=line,
                        rule_id=rule_id,
                        message=message,
                        original_severity=severity,
                        unified_severity=unified_severity,
                        cwe=cwe
                    ))
        
        except Exception as e:
            print(f"Error parsing Semgrep SARIF: {e}")
        
        return findings


class ResultsAnalyzer:
    """Analyze and summarize findings"""
    
    def __init__(self, findings: List[Finding]):
        self.findings = findings
    
    def count_by_severity(self) -> Dict[str, int]:
        """Count findings by unified severity"""
        counts = defaultdict(int)
        for finding in self.findings:
            counts[finding.unified_severity] += 1
        return dict(counts)
    
    def count_by_tool(self) -> Dict[str, int]:
        """Count findings by tool"""
        counts = defaultdict(int)
        for finding in self.findings:
            counts[finding.tool] += 1
        return dict(counts)
    
    def count_by_cwe(self) -> Dict[str, int]:
        """Count findings by CWE"""
        counts = defaultdict(int)
        for finding in self.findings:
            if finding.cwe:
                counts[finding.cwe] += 1
        return dict(sorted(counts.items(), key=lambda x: x[1], reverse=True))
    
    def get_top_findings(self, n: int = 10, severity: Optional[str] = None) -> List[Finding]:
        """Get top N findings, optionally filtered by severity"""
        filtered = self.findings
        if severity:
            filtered = [f for f in filtered if f.unified_severity == severity]
        
        # Sort by severity priority
        severity_order = {s: i for i, s in enumerate(SeverityMapper.SEVERITY_ORDER)}
        sorted_findings = sorted(
            filtered,
            key=lambda x: severity_order.get(x.unified_severity, 0),
            reverse=True
        )
        
        return sorted_findings[:n]
    
    def generate_report(self) -> str:
        """Generate a summary report"""
        report = []
        report.append("=" * 70)
        report.append("SECURITY ANALYSIS SUMMARY")
        report.append("=" * 70)
        report.append("")
        
        # Total findings
        report.append(f"Total Findings: {len(self.findings)}")
        report.append("")
        
        # By severity
        report.append("Distribution by Unified Severity:")
        severity_counts = self.count_by_severity()
        for severity in SeverityMapper.SEVERITY_ORDER[::-1]:  # Reverse order
            count = severity_counts.get(severity, 0)
            report.append(f"  {severity:12s}: {count:4d}")
        report.append("")
        
        # By tool
        report.append("Distribution by Tool:")
        tool_counts = self.count_by_tool()
        for tool, count in tool_counts.items():
            report.append(f"  {tool:12s}: {count:4d}")
        report.append("")
        
        # Top CWEs
        report.append("Top 10 CWEs:")
        cwe_counts = self.count_by_cwe()
        for i, (cwe, count) in enumerate(list(cwe_counts.items())[:10], 1):
            report.append(f"  {i:2d}. {cwe:12s}: {count:4d}")
        report.append("")
        
        # Top critical findings
        report.append("Top 5 Critical Findings:")
        critical = self.get_top_findings(5, 'CRITICAL')
        if critical:
            for i, finding in enumerate(critical, 1):
                report.append(f"  {i}. [{finding.tool}] {finding.rule_id}")
                report.append(f"     File: {finding.file}:{finding.line}")
                report.append(f"     {finding.message[:70]}")
                if finding.cwe:
                    report.append(f"     CWE: {finding.cwe}")
                report.append("")
        else:
            report.append("  No critical findings")
            report.append("")
        
        report.append("=" * 70)
        
        return "\n".join(report)


def main():
    parser = argparse.ArgumentParser(description='Analyze security scan results')
    parser.add_argument('--cppcheck', type=Path, help='Path to Cppcheck XML file')
    parser.add_argument('--flawfinder', type=Path, help='Path to Flawfinder SARIF file')
    parser.add_argument('--semgrep', type=Path, help='Path to Semgrep SARIF file')
    parser.add_argument('--output', type=Path, help='Output report file (optional)')
    
    args = parser.parse_args()
    
    all_findings = []
    
    # Parse each tool's output
    if args.cppcheck and args.cppcheck.exists():
        print(f"Parsing Cppcheck results from {args.cppcheck}...")
        all_findings.extend(ResultsParser.parse_cppcheck_xml(args.cppcheck))
    
    if args.flawfinder and args.flawfinder.exists():
        print(f"Parsing Flawfinder results from {args.flawfinder}...")
        all_findings.extend(ResultsParser.parse_flawfinder_sarif(args.flawfinder))
    
    if args.semgrep and args.semgrep.exists():
        print(f"Parsing Semgrep results from {args.semgrep}...")
        all_findings.extend(ResultsParser.parse_semgrep_sarif(args.semgrep))
    
    if not all_findings:
        print("No findings to analyze!")
        return
    
    # Analyze results
    analyzer = ResultsAnalyzer(all_findings)
    report = analyzer.generate_report()
    
    # Print report
    print("\n" + report)
    
    # Save to file if specified
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"\nReport saved to {args.output}")


if __name__ == '__main__':
    main()
