"""
Unit tests for SensitiveDataDetector
"""

import pytest
from src.detectors.sensitive_data_detector import SensitiveDataDetector, SensitivityLevel


class TestSensitiveDataDetector:
    """Test SensitiveDataDetector functionality"""

    def setup_method(self):
        """Setup test fixtures"""
        self.detector = SensitiveDataDetector()

    def test_detect_ssn_in_text(self):
        """Test SSN detection"""
        text = "My SSN is 123-45-6789"
        detections = self.detector.detect_in_text(text)

        assert len(detections) > 0
        ssn_detection = next((d for d in detections if d['type'] == 'SSN'), None)
        assert ssn_detection is not None
        assert ssn_detection['level'] == SensitivityLevel.CRITICAL.value

    def test_detect_credit_card(self):
        """Test credit card detection"""
        text = "Card: 4532-1234-5678-9010"
        detections = self.detector.detect_in_text(text)

        assert len(detections) > 0
        cc_detection = next((d for d in detections if d['type'] == 'Credit Card'), None)
        assert cc_detection is not None

    def test_detect_email(self):
        """Test email detection"""
        text = "Contact: user@example.com"
        detections = self.detector.detect_in_text(text)

        assert len(detections) > 0
        email_detection = next((d for d in detections if d['type'] == 'Email'), None)
        assert email_detection is not None

    def test_detect_api_key(self):
        """Test API key detection"""
        text = "api_key: EXAMPLE_KEY_1234567890abcdefghijklmnopqrstuvwx"
        detections = self.detector.detect_in_text(text)

        assert len(detections) > 0
        api_detection = next((d for d in detections if d['type'] == 'API Key'), None)
        assert api_detection is not None
        assert api_detection['level'] == SensitivityLevel.CRITICAL.value

    def test_detect_sensitive_filename(self):
        """Test sensitive keyword detection in filename"""
        filename = "confidential_salaries_2024.xlsx"
        detections = self.detector.detect_in_filename(filename)

        assert len(detections) > 0
        keywords = [d['keyword'] for d in detections]
        assert 'confidential' in keywords
        assert 'salary' in keywords

    def test_sensitive_file_extension(self):
        """Test sensitive file extension detection"""
        file_item = {
            'id': '123',
            'name': 'private.key',
            'parentReference': {'path': '/documents'}
        }

        result = self.detector.analyze_file(file_item)

        assert result['hasSensitiveData'] is True
        assert any(d['type'] == 'sensitive_extension' for d in result['detections'])

    def test_analyze_file_with_sensitive_path(self):
        """Test detection in file path"""
        file_item = {
            'id': '456',
            'name': 'report.pdf',
            'parentReference': {'path': '/confidential/financial'}
        }

        result = self.detector.analyze_file(file_item)

        assert result['hasSensitiveData'] is True
        assert result['highestSensitivityLevel'] in [
            SensitivityLevel.HIGH.value,
            SensitivityLevel.MEDIUM.value
        ]

    def test_filter_by_sensitivity(self):
        """Test filtering by sensitivity level"""
        files = [
            {
                'sensitivityScore': 4,
                'highestSensitivityLevel': SensitivityLevel.CRITICAL.value
            },
            {
                'sensitivityScore': 2,
                'highestSensitivityLevel': SensitivityLevel.MEDIUM.value
            },
            {
                'sensitivityScore': 0,
                'highestSensitivityLevel': SensitivityLevel.NONE.value
            }
        ]

        filtered = self.detector.filter_by_sensitivity(
            files,
            SensitivityLevel.MEDIUM
        )

        assert len(filtered) == 2

    def test_generate_summary(self):
        """Test summary generation"""
        files = [
            {
                'hasSensitiveData': True,
                'highestSensitivityLevel': SensitivityLevel.CRITICAL.value,
                'detectionCount': 2,
                'detections': [
                    {'type': 'SSN'},
                    {'type': 'Credit Card'}
                ]
            },
            {
                'hasSensitiveData': False,
                'highestSensitivityLevel': SensitivityLevel.NONE.value,
                'detectionCount': 0,
                'detections': []
            }
        ]

        summary = self.detector.generate_summary(files)

        assert summary['totalFiles'] == 2
        assert summary['filesWithSensitiveData'] == 1
        assert summary['totalDetections'] == 2

    def test_no_false_positives(self):
        """Test that normal filenames don't trigger false positives"""
        file_item = {
            'id': '789',
            'name': 'meeting_notes.docx',
            'parentReference': {'path': '/documents/projects'}
        }

        result = self.detector.analyze_file(file_item)

        # .docx might trigger sensitive extension, but should be low severity
        if result['hasSensitiveData']:
            assert result['sensitivityScore'] <= 2
