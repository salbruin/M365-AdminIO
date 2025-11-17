"""
Sensitive Data Detector Module
Detects potentially sensitive information in file names and metadata
"""

import re
import logging
from typing import Dict, Any, List, Set
from enum import Enum

logger = logging.getLogger(__name__)


class SensitivityLevel(Enum):
    """Sensitivity levels for detected data"""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class SensitiveDataDetector:
    """
    Detects sensitive data patterns in file names and metadata
    Uses regex patterns to identify PII, credentials, and confidential data
    """

    # Default sensitive data patterns
    DEFAULT_PATTERNS = {
        # Personal Identifiable Information (PII)
        'SSN': {
            'pattern': r'\b\d{3}-\d{2}-\d{4}\b',
            'level': SensitivityLevel.CRITICAL,
            'description': 'Social Security Number'
        },
        'Credit Card': {
            'pattern': r'\b(?:\d{4}[-\s]?){3}\d{4}\b',
            'level': SensitivityLevel.CRITICAL,
            'description': 'Credit Card Number'
        },
        'Email': {
            'pattern': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
            'level': SensitivityLevel.MEDIUM,
            'description': 'Email Address'
        },
        'Phone': {
            'pattern': r'\b(?:\+?1[-.]?)?\(?([0-9]{3})\)?[-.]?([0-9]{3})[-.]?([0-9]{4})\b',
            'level': SensitivityLevel.MEDIUM,
            'description': 'Phone Number'
        },

        # Credentials and Keys
        'API Key': {
            'pattern': r'\b(?:api[_-]?key|apikey|api[_-]?token)[\s:=]+[\'"]?([a-zA-Z0-9_\-]{20,})[\'"]?\b',
            'level': SensitivityLevel.CRITICAL,
            'description': 'API Key'
        },
        'AWS Access Key': {
            'pattern': r'\b(AKIA[0-9A-Z]{16})\b',
            'level': SensitivityLevel.CRITICAL,
            'description': 'AWS Access Key'
        },
        'Private Key': {
            'pattern': r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----',
            'level': SensitivityLevel.CRITICAL,
            'description': 'Private Cryptographic Key'
        },
        'Password': {
            'pattern': r'\b(?:password|passwd|pwd)[\s:=]+[\'"]?([^\s\'"]{6,})[\'"]?\b',
            'level': SensitivityLevel.CRITICAL,
            'description': 'Password'
        },
        'Token': {
            'pattern': r'\b(?:bearer|token|jwt)[\s:=]+[\'"]?([a-zA-Z0-9_\-\.]{20,})[\'"]?\b',
            'level': SensitivityLevel.CRITICAL,
            'description': 'Authentication Token'
        },

        # Financial Information
        'Bank Account': {
            'pattern': r'\b(?:account|acct)[\s#:]+\d{8,17}\b',
            'level': SensitivityLevel.HIGH,
            'description': 'Bank Account Number'
        },
        'IBAN': {
            'pattern': r'\b[A-Z]{2}\d{2}[A-Z0-9]{4}\d{7}([A-Z0-9]?){0,16}\b',
            'level': SensitivityLevel.HIGH,
            'description': 'International Bank Account Number'
        },

        # Medical Information
        'Medical Record': {
            'pattern': r'\b(?:MRN|medical[_-]?record)[\s#:]+\d{6,10}\b',
            'level': SensitivityLevel.CRITICAL,
            'description': 'Medical Record Number'
        },

        # Government IDs
        'Passport': {
            'pattern': r'\b[A-Z]{1,2}\d{6,9}\b',
            'level': SensitivityLevel.HIGH,
            'description': 'Passport Number'
        },
        'Driver License': {
            'pattern': r'\b(?:DL|driver[_-]?license)[\s#:]+[A-Z0-9]{5,20}\b',
            'level': SensitivityLevel.HIGH,
            'description': 'Driver License Number'
        },
    }

    # Filename keywords that suggest sensitive content
    SENSITIVE_KEYWORDS = {
        'confidential': SensitivityLevel.HIGH,
        'secret': SensitivityLevel.HIGH,
        'private': SensitivityLevel.HIGH,
        'internal': SensitivityLevel.MEDIUM,
        'restricted': SensitivityLevel.HIGH,
        'classified': SensitivityLevel.CRITICAL,
        'sensitive': SensitivityLevel.HIGH,
        'proprietary': SensitivityLevel.HIGH,
        'personal': SensitivityLevel.MEDIUM,
        'salary': SensitivityLevel.HIGH,
        'payroll': SensitivityLevel.HIGH,
        'ssn': SensitivityLevel.CRITICAL,
        'tax': SensitivityLevel.HIGH,
        'medical': SensitivityLevel.HIGH,
        'health': SensitivityLevel.MEDIUM,
        'financial': SensitivityLevel.HIGH,
        'banking': SensitivityLevel.HIGH,
        'password': SensitivityLevel.CRITICAL,
        'credential': SensitivityLevel.CRITICAL,
    }

    def __init__(self, custom_patterns: Dict[str, Dict[str, Any]] = None):
        """
        Initialize sensitive data detector

        Args:
            custom_patterns: Additional custom patterns to detect
        """
        self.patterns = self.DEFAULT_PATTERNS.copy()

        if custom_patterns:
            self.patterns.update(custom_patterns)

        # Compile regex patterns for efficiency
        self.compiled_patterns = {}
        for name, config in self.patterns.items():
            try:
                self.compiled_patterns[name] = {
                    'regex': re.compile(config['pattern'], re.IGNORECASE),
                    'level': config['level'],
                    'description': config['description']
                }
            except re.error as e:
                logger.warning(f"Invalid regex pattern for {name}: {str(e)}")

    def detect_in_text(self, text: str) -> List[Dict[str, Any]]:
        """
        Detect sensitive data patterns in text

        Args:
            text: Text to analyze

        Returns:
            List of detected patterns with details
        """
        if not text:
            return []

        detections = []

        for name, pattern_config in self.compiled_patterns.items():
            matches = pattern_config['regex'].findall(text)

            if matches:
                detections.append({
                    'type': name,
                    'description': pattern_config['description'],
                    'level': pattern_config['level'].value,
                    'matchCount': len(matches),
                    'examples': matches[:3]  # Include up to 3 examples
                })

        return detections

    def detect_in_filename(self, filename: str) -> List[Dict[str, Any]]:
        """
        Detect sensitive keywords in filename

        Args:
            filename: Filename to analyze

        Returns:
            List of detected keywords with sensitivity levels
        """
        if not filename:
            return []

        filename_lower = filename.lower()
        detections = []

        for keyword, level in self.SENSITIVE_KEYWORDS.items():
            if keyword in filename_lower:
                detections.append({
                    'type': 'sensitive_keyword',
                    'keyword': keyword,
                    'description': f'Filename contains sensitive keyword: {keyword}',
                    'level': level.value
                })

        return detections

    def analyze_file(self, file_item: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze a file for sensitive data indicators

        Args:
            file_item: File item from OneDrive

        Returns:
            Analysis results with detected sensitive data
        """
        filename = file_item.get('name', '')
        file_path = file_item.get('parentReference', {}).get('path', '')

        # Detect in filename
        filename_detections = self.detect_in_filename(filename)

        # Detect in file path
        path_detections = self.detect_in_filename(file_path)

        # Combine detections
        all_detections = filename_detections + path_detections

        # Determine highest sensitivity level
        level_order = {
            SensitivityLevel.CRITICAL.value: 4,
            SensitivityLevel.HIGH.value: 3,
            SensitivityLevel.MEDIUM.value: 2,
            SensitivityLevel.LOW.value: 1,
            SensitivityLevel.NONE.value: 0
        }

        highest_level = SensitivityLevel.NONE.value
        if all_detections:
            highest_level = max(
                all_detections,
                key=lambda d: level_order.get(d['level'], 0)
            )['level']

        # Check file extension for potentially sensitive types
        file_ext = filename.split('.')[-1].lower() if '.' in filename else ''
        sensitive_extensions = {
            'key', 'pem', 'p12', 'pfx', 'cer', 'crt',  # Certificates/keys
            'sql', 'db', 'sqlite',  # Databases
            'env', 'config', 'conf',  # Config files
            'xlsx', 'xls', 'csv',  # Spreadsheets (often contain PII)
        }

        if file_ext in sensitive_extensions:
            all_detections.append({
                'type': 'sensitive_extension',
                'extension': file_ext,
                'description': f'File type commonly contains sensitive data: .{file_ext}',
                'level': SensitivityLevel.MEDIUM.value
            })

            if highest_level == SensitivityLevel.NONE.value:
                highest_level = SensitivityLevel.MEDIUM.value

        return {
            'fileId': file_item.get('id'),
            'fileName': filename,
            'filePath': file_path,
            'hasSensitiveData': len(all_detections) > 0,
            'detections': all_detections,
            'detectionCount': len(all_detections),
            'highestSensitivityLevel': highest_level,
            'sensitivityScore': level_order.get(highest_level, 0)
        }

    def filter_by_sensitivity(self, analyzed_files: List[Dict[str, Any]],
                             min_level: SensitivityLevel = SensitivityLevel.LOW) -> List[Dict[str, Any]]:
        """
        Filter files by minimum sensitivity level

        Args:
            analyzed_files: List of analyzed file results
            min_level: Minimum sensitivity level to include

        Returns:
            Filtered list of files
        """
        level_order = {
            SensitivityLevel.CRITICAL.value: 4,
            SensitivityLevel.HIGH.value: 3,
            SensitivityLevel.MEDIUM.value: 2,
            SensitivityLevel.LOW.value: 1,
            SensitivityLevel.NONE.value: 0
        }

        min_score = level_order.get(min_level.value, 0)

        return [
            f for f in analyzed_files
            if f['sensitivityScore'] >= min_score
        ]

    def generate_summary(self, analyzed_files: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generate summary statistics for sensitive data analysis

        Args:
            analyzed_files: List of analyzed file results

        Returns:
            Summary statistics
        """
        total_files = len(analyzed_files)
        files_with_sensitive_data = sum(1 for f in analyzed_files if f['hasSensitiveData'])

        sensitivity_counts = {
            SensitivityLevel.CRITICAL.value: 0,
            SensitivityLevel.HIGH.value: 0,
            SensitivityLevel.MEDIUM.value: 0,
            SensitivityLevel.LOW.value: 0,
            SensitivityLevel.NONE.value: 0
        }

        detection_types = {}

        for file in analyzed_files:
            level = file['highestSensitivityLevel']
            sensitivity_counts[level] = sensitivity_counts.get(level, 0) + 1

            for detection in file.get('detections', []):
                det_type = detection.get('type')
                detection_types[det_type] = detection_types.get(det_type, 0) + 1

        return {
            'totalFiles': total_files,
            'filesWithSensitiveData': files_with_sensitive_data,
            'filesWithoutSensitiveData': total_files - files_with_sensitive_data,
            'sensitivityDistribution': sensitivity_counts,
            'detectionTypes': detection_types,
            'totalDetections': sum(f['detectionCount'] for f in analyzed_files)
        }
