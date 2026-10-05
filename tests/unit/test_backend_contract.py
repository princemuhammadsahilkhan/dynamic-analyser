"""Unit tests for backend contract modeling and Supabase static contract mapping."""

import json
import unittest
from unittest.mock import MagicMock, patch

from dynamic_analysis.backend_contract import (
    AuthDataFlow,
    BackendContractInventory,
    BackendOperation,
    BackendResource,
    RealtimeResource,
    StorageResource,
    SupabaseContractMapper,
)
from dynamic_analysis.observation import EvidenceType


class TestBackendContractModel(unittest.TestCase):
    """Test suite for backend contract data structures and serialization."""

    def test_backend_operation_creation(self):
        op = BackendOperation(operation_type="select", details="courses table select")
        self.assertEqual(op.operation_type, "select")
        self.assertEqual(op.details, "courses table select")

    def test_backend_resource_creation(self):
        res = BackendResource(
            resource_name="courses",
            resource_type="table",
            operations=["select", "insert"],
            associated_components=["CourseManagementScreen"],
            role_classification="teacher",
            confidence="VERIFIED STATIC REFERENCE",
        )
        self.assertEqual(res.resource_name, "courses")
        self.assertEqual(res.role_classification, "teacher")

    def test_backend_contract_inventory_to_dict(self):
        inventory = BackendContractInventory(
            target_apk="apks/app-release.apk",
            primary_backend_url="https://tqzoozpckrmmprwnhweg.supabase.co",
            supabase_tables=[
                BackendResource(
                    resource_name="users",
                    resource_type="table",
                    operations=["select"],
                    associated_components=["LoginScreen"],
                    role_classification="shared",
                    confidence="VERIFIED STATIC REFERENCE",
                )
            ],
            auth_flows=[
                AuthDataFlow(
                    stage="UI Authentication Screen",
                    source_component="LoginScreen",
                    target_mechanism="Form Validation",
                    evidence_references=["LoginScreen"],
                    confidence="VERIFIED STATIC REFERENCE",
                )
            ],
            storage_resources=[
                StorageResource(
                    bucket_name="profile-images",
                    path_pattern="/storage/v1/object/public/profile-images/",
                    operations=["fetch"],
                    associated_components=["StudentMainScreen"],
                    confidence="VERIFIED STATIC REFERENCE",
                )
            ],
            realtime_resources=[
                RealtimeResource(
                    channel_type="websocket",
                    endpoint_or_name="/realtime/v1",
                    operations=["subscribe"],
                    associated_components=["StudentMainScreen"],
                    confidence="VERIFIED STATIC REFERENCE",
                )
            ],
            edge_functions=[],
        )

        d = inventory.to_dict()
        self.assertEqual(d["target_apk"], "apks/app-release.apk")
        self.assertEqual(d["primary_backend_url"], "https://tqzoozpckrmmprwnhweg.supabase.co")
        self.assertEqual(len(d["supabase_tables"]), 1)
        self.assertEqual(d["supabase_tables"][0]["resource_name"], "users")
        self.assertEqual(len(d["auth_flows"]), 1)
        self.assertEqual(len(d["storage_resources"]), 1)
        self.assertEqual(len(d["realtime_resources"]), 1)

    def test_backend_contract_inventory_to_evidence_items(self):
        inventory = BackendContractInventory(
            target_apk="apks/app-release.apk",
            primary_backend_url="https://tqzoozpckrmmprwnhweg.supabase.co",
            supabase_tables=[
                BackendResource(
                    resource_name="courses",
                    resource_type="table",
                    operations=["select"],
                    associated_components=["StudentMainScreen"],
                    role_classification="shared",
                    confidence="VERIFIED STATIC REFERENCE",
                )
            ],
            auth_flows=[
                AuthDataFlow(
                    stage="UI Auth Screen",
                    source_component="LoginScreen",
                    target_mechanism="Validation",
                    evidence_references=["LoginScreen"],
                    confidence="VERIFIED STATIC REFERENCE",
                )
            ],
            storage_resources=[
                StorageResource(
                    bucket_name="mentorcraft-images",
                    path_pattern="/storage/v1/object/mentorcraft-images/",
                    operations=["upload"],
                    associated_components=["CourseManagementScreen"],
                    confidence="VERIFIED STATIC REFERENCE",
                )
            ],
            realtime_resources=[
                RealtimeResource(
                    channel_type="websocket",
                    endpoint_or_name="/realtime/v1",
                    operations=["listen"],
                    associated_components=["StudentMainScreen"],
                    confidence="VERIFIED STATIC REFERENCE",
                )
            ],
            edge_functions=[],
        )

        items = inventory.to_evidence_items(serial="emulator-5554")
        self.assertGreaterEqual(len(items), 5)
        types = [item.evidence_type for item in items]
        self.assertIn(EvidenceType.BACKEND_CONTRACT.value, types)
        self.assertIn(EvidenceType.SUPABASE_RESOURCE.value, types)
        self.assertIn(EvidenceType.AUTH_DATA_FLOW.value, types)
        self.assertIn(EvidenceType.STORAGE_INVENTORY.value, types)
        self.assertIn(EvidenceType.REALTIME_INVENTORY.value, types)

    @patch.object(SupabaseContractMapper, "_extract_binary_strings")
    def test_supabase_contract_mapper_analyze(self, mock_extract):
        mock_extract.return_value = (
            "https://tqzoozpckrmmprwnhweg.supabase.co\n"
            "users\ncourses\nenrollments\nquizzes\nannouncements\ndiscussions\n"
            "profile-images\nmentorcraft-images\n/realtime/v1\n"
            "GoTrueClient\nsignUp\nonAuthStateChange\ngotrue_async_storage\n"
        )
        mapper = SupabaseContractMapper("apks/app-release.apk")
        inventory = mapper.analyze()

        self.assertEqual(inventory.primary_backend_url, "https://tqzoozpckrmmprwnhweg.supabase.co")
        self.assertGreaterEqual(len(inventory.supabase_tables), 6)
        table_names = [t.resource_name for t in inventory.supabase_tables]
        self.assertIn("courses", table_names)
        self.assertIn("users", table_names)
        self.assertEqual(len(inventory.storage_resources), 2)
        self.assertEqual(len(inventory.realtime_resources), 1)


if __name__ == "__main__":
    unittest.main()
