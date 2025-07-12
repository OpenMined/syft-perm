"""Test that all tutorial notebooks execute without errors."""

from pathlib import Path

import nbformat
import pytest
from nbconvert.preprocessors import ExecutePreprocessor

TUTORIALS_DIR = Path(__file__).parent.parent / "tutorials"
TIMEOUT = 600  # 10 minutes per notebook


def get_notebooks():
    """Get all notebook files in the tutorials directory."""
    return sorted([f for f in TUTORIALS_DIR.glob("*.ipynb") if not f.name.startswith(".")])


@pytest.mark.parametrize("notebook_path", get_notebooks())
def test_notebook_execution(notebook_path):
    """Test that a notebook executes without errors."""
    with open(notebook_path) as f:
        nb = nbformat.read(f, as_version=4)

    ep = ExecutePreprocessor(timeout=TIMEOUT, kernel_name="python3")

    try:
        # Execute the notebook
        ep.preprocess(nb, {"metadata": {"path": str(notebook_path.parent)}})
    except Exception as e:
        pytest.fail(f"Error executing notebook {notebook_path.name}: {str(e)}")
