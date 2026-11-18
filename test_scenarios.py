"""
Automated Test Suite for Live Video Integrity & Tamper Detection System.
Executes test scenarios:
- Test 1: Original authentic video session (Expect PASS)
- Test 2: Frame pixel modification (Expect DETECTED)
- Test 3: Frame deletion (Expect DETECTED)
- Test 4: Frame sequence swap / reorder (Expect DETECTED)
- Test 5: Audit log hash corruption (Expect DETECTED)
"""

import os
import sys
import shutil
import unittest
from core.audit_logger import AuditLogger
from core.video_engine import VideoStreamSource
from core.hash_chain import GENESIS_HASH, sha256_bytes, create_chain_hash
from core.verifier_engine import VideoVerifier
import tamper_simulator


TEST_DIR = "test_evidence"


class TestVideoIntegritySystem(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        """Generates a clean synthetic video evidence dataset (10 frames)."""
        cls.logger = AuditLogger(base_dir=TEST_DIR)
        cls.logger.open_session(reset=True)
        stream = VideoStreamSource(mode="synthetic")

        previous_hash = GENESIS_HASH
        for i in range(1, 11):
            ret, frame = stream.read()
            assert ret and frame is not None
            f_hash = sha256_bytes(frame.tobytes())
            c_hash = create_chain_hash(previous_hash, i, f_hash)
            cls.logger.log_frame(i, f_hash, c_hash, frame=frame)
            previous_hash = c_hash

        stream.release()
        cls.logger.close_session()

        # Point tamper simulator paths to TEST_DIR
        tamper_simulator.FRAME_DIR = os.path.join(TEST_DIR, "frames")
        tamper_simulator.LOG_FILE = os.path.join(TEST_DIR, "hash_log.jsonl")
        tamper_simulator.SNAPSHOT_DIR = os.path.join(TEST_DIR, ".snapshot_clean")

    @classmethod
    def tearDownClass(cls):
        """Cleanup test directory."""
        if os.path.exists(TEST_DIR):
            shutil.rmtree(TEST_DIR)

    def setUp(self):
        """Ensure pristine snapshot is restored before each test."""
        self.logger.restore_clean_snapshot()

    def test_01_authentic_video(self):
        """Test 1: Pristine video must pass 100% with no violations."""
        verifier = VideoVerifier(base_dir=TEST_DIR)
        result = verifier.verify()
        self.assertTrue(result.is_valid, "Authentic video should pass verification")
        self.assertEqual(result.total_checked, 10)
        self.assertEqual(result.authentic_count, 10)
        self.assertEqual(result.tampered_count, 0)
        self.assertEqual(result.missing_count, 0)
        self.assertTrue(result.manifest_verified)
        print("\n[TEST 1 PASSED] Pristine video integrity 100% verified.")

    def test_02_modified_frame(self):
        """Test 2: Modifying pixels in Frame 4 must be detected."""
        tamper_simulator.modify_frame(frame_index=4, attack_type="watermark")
        verifier = VideoVerifier(base_dir=TEST_DIR)
        result = verifier.verify()
        self.assertFalse(result.is_valid, "Modified frame must fail verification")
        self.assertGreaterEqual(result.tampered_count, 1)
        self.assertEqual(result.first_violation_index, 4)
        print("\n[TEST 2 PASSED] Tampered frame #4 correctly detected.")

    def test_03_deleted_frame(self):
        """Test 3: Deleting Frame 5 must trigger a MISSING FRAME alert."""
        tamper_simulator.delete_frame(frame_index=5)
        verifier = VideoVerifier(base_dir=TEST_DIR)
        result = verifier.verify()
        self.assertFalse(result.is_valid, "Deleted frame must fail verification")
        self.assertGreaterEqual(result.missing_count, 1)
        self.assertEqual(result.first_violation_index, 5)
        print("\n[TEST 3 PASSED] Missing frame #5 correctly flagged.")

    def test_04_swapped_frames(self):
        """Test 4: Swapping Frame 6 and Frame 7 must be detected."""
        tamper_simulator.swap_frames(frame_a=6, frame_b=7)
        verifier = VideoVerifier(base_dir=TEST_DIR)
        result = verifier.verify()
        self.assertFalse(result.is_valid, "Reordered frames must fail verification")
        self.assertGreaterEqual(result.tampered_count, 2)
        print("\n[TEST 4 PASSED] Reordered frames #6 and #7 correctly detected.")

    def test_05_corrupted_log(self):
        """Test 5: Maliciously altering the audit log must be detected."""
        tamper_simulator.corrupt_log(line_number=3)
        verifier = VideoVerifier(base_dir=TEST_DIR)
        result = verifier.verify()
        self.assertFalse(result.is_valid, "Forged log must fail verification")
        self.assertGreaterEqual(result.chain_broken_count + result.tampered_count, 1)
        print("\n[TEST 5 PASSED] Forged audit log detected via cryptographic chain rupture.")

    def test_06_digital_masking_attack(self):
        """Test 6: Digital box masking must trigger both hash mismatch and mask detection."""
        tamper_simulator.modify_frame(frame_index=3, attack_type="mask_box")
        verifier = VideoVerifier(base_dir=TEST_DIR)
        result = verifier.verify()
        self.assertFalse(result.is_valid, "Masked video must fail verification")
        self.assertGreaterEqual(result.masked_count, 1)
        self.assertEqual(result.first_violation_index, 3)
        self.assertLess(result.accuracy_percent, 100.0)
        # Check that Frame 3 status identifies masking
        f3 = [f for f in result.frame_results if f.index == 3][0]
        self.assertTrue(f3.is_masked)
        self.assertEqual(f3.mask_type, "DIGITAL_BOX_MASK")
        print("\n[TEST 6 PASSED] Digital occlusion box mask detected alongside hash mismatch!")

    def test_07_lens_occlusion_attack(self):
        """Test 7: Camera lens blackout / occlusion must be detected."""
        tamper_simulator.modify_frame(frame_index=2, attack_type="mask_lens")
        verifier = VideoVerifier(base_dir=TEST_DIR)
        result = verifier.verify()
        self.assertFalse(result.is_valid, "Occluded video must fail verification")
        self.assertGreaterEqual(result.masked_count, 1)
        f2 = [f for f in result.frame_results if f.index == 2][0]
        self.assertTrue(f2.is_masked)
        self.assertEqual(f2.mask_type, "LENS_OCCLUSION")
        print("\n[TEST 7 PASSED] Camera lens blackout occlusion caught by verifier!")


if __name__ == "__main__":
    print("\n========================================================")
    print(" RUNNING AUTOMATED VIDEO INTEGRITY VERIFICATION SUITE")
    print("========================================================")
    unittest.main(verbosity=2)
