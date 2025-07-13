"""Test suite for terminal node behavior with child yaml files."""

import shutil
import tempfile
import unittest
from pathlib import Path

import syft_perm


class TestTerminalNodeOverride(unittest.TestCase):
    """Test that terminal nodes properly ignore child yaml files."""

    def setUp(self):
        """Set up test directory structure."""
        self.test_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.test_dir)

    def test_terminal_node_ignores_child_yaml_files(self):
        """Test the exact scenario from the user's example."""
        # Create directory structure
        datasites_dir = Path(self.test_dir) / "SyftBox" / "datasites"
        datasites_dir.mkdir(parents=True)

        user_datasite = datasites_dir / "liamtrask@gmail.com"
        chat_folder = user_datasite / "chat"
        inner_dialogue_folder = chat_folder / "inner_dialogue"
        inner_dialogue_folder.mkdir(parents=True)

        # Create test files
        convo1_file = chat_folder / "convo1.txt"
        convo1_file.write_text("conversation 1")

        convo2_file = inner_dialogue_folder / "convo2.txt "  # Note: space at end like user example
        convo2_file.write_text("conversation 2")

        # Grant read access to andrew@openmined.org at the chat folder level
        chat_obj = syft_perm.open(chat_folder)
        chat_obj.grant_read_access("andrew@openmined.org", force=True)

        # Verify the permissions work
        self.assertTrue(chat_obj.has_read_access("andrew@openmined.org"))

        # Check that convo1.txt inherits the permission
        convo1_obj = syft_perm.open(convo1_file)
        self.assertTrue(convo1_obj.has_read_access("andrew@openmined.org"))

        # Check that convo2.txt also inherits the permission
        convo2_obj = syft_perm.open(convo2_file)
        self.assertTrue(convo2_obj.has_read_access("andrew@openmined.org"))

        # Now revoke access for convo2.txt specifically
        convo2_obj.revoke_read_access("andrew@openmined.org")

        # Clear cache to ensure fresh permission check
        from syft_perm._impl import clear_permission_cache

        clear_permission_cache()

        # Without terminal, convo2.txt should lose access
        convo2_obj_after_revoke = syft_perm.open(convo2_file)
        self.assertFalse(convo2_obj_after_revoke.has_read_access("andrew@openmined.org"))

        # Now set terminal=True on the chat folder
        chat_obj.set_terminal(True)

        # Verify terminal is set
        self.assertTrue(chat_obj.get_terminal())

        # Clear cache again to ensure fresh permission checks
        clear_permission_cache()

        # Now convo1.txt should still have access
        convo1_obj_refreshed = syft_perm.open(convo1_file)
        self.assertTrue(convo1_obj_refreshed.has_read_access("andrew@openmined.org"))

        # And convo2.txt should ALSO have access because the terminal node
        # at /chat/ should ignore the yaml file in /chat/inner_dialogue/
        convo2_obj_refreshed = syft_perm.open(convo2_file)
        self.assertTrue(convo2_obj_refreshed.has_read_access("andrew@openmined.org"))

        # Note: explain_permissions might still show the child yaml file rules
        # but has_read_access correctly returns True because terminal node overrides

    def test_terminal_node_with_specific_pattern(self):
        """Test terminal node with specific file patterns."""
        # Create test structure
        datasites_dir = Path(self.test_dir) / "SyftBox" / "datasites"
        datasites_dir.mkdir(parents=True)

        user_datasite = datasites_dir / "testuser@example.com"
        docs_folder = user_datasite / "docs"
        private_folder = docs_folder / "private"
        private_folder.mkdir(parents=True)

        # Create files
        public_doc = docs_folder / "public.txt"
        public_doc.write_text("public document")

        private_doc = private_folder / "secret.txt"
        private_doc.write_text("private document")

        # Set up permissions: docs folder grants read to all users
        docs_obj = syft_perm.open(docs_folder)
        docs_obj.grant_read_access("user1@example.com", force=True)
        docs_obj.set_terminal(True)

        # Try to revoke access in the private subfolder
        private_obj = syft_perm.open(private_folder)
        private_obj.revoke_read_access("user1@example.com")

        # Both files should still have access because docs is terminal
        public_obj = syft_perm.open(public_doc)
        private_doc_obj = syft_perm.open(private_doc)

        self.assertTrue(public_obj.has_read_access("user1@example.com"))
        self.assertTrue(private_doc_obj.has_read_access("user1@example.com"))

    def test_terminal_node_empty_permissions(self):
        """Test terminal node with no matching rules stops inheritance."""
        # Create test structure
        datasites_dir = Path(self.test_dir) / "SyftBox" / "datasites"
        datasites_dir.mkdir(parents=True)

        user_datasite = datasites_dir / "testuser@example.com"
        parent_folder = user_datasite / "parent"
        terminal_folder = parent_folder / "terminal"
        child_folder = terminal_folder / "child"
        child_folder.mkdir(parents=True)

        test_file = child_folder / "test.txt"
        test_file.write_text("test content")

        # Grant permission at parent level
        parent_obj = syft_perm.open(parent_folder)
        parent_obj.grant_read_access("viewer@example.com", force=True)

        # Set terminal folder with no rules
        terminal_obj = syft_perm.open(terminal_folder)
        terminal_obj.set_terminal(True)

        # File should NOT have access because terminal node has no matching rules
        file_obj = syft_perm.open(test_file)
        self.assertFalse(file_obj.has_read_access("viewer@example.com"))

        # But if we add a rule to the terminal node, it should work
        terminal_obj.grant_read_access("viewer@example.com", force=True)

        # Now the file should have access
        file_obj_refreshed = syft_perm.open(test_file)
        self.assertTrue(file_obj_refreshed.has_read_access("viewer@example.com"))


if __name__ == "__main__":
    unittest.main()
