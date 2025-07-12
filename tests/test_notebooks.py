"""Test that all tutorial notebooks execute without errors."""

import sys
from pathlib import Path

import nbformat
import pytest
from jupyter_client.kernelspec import KernelSpecManager
from nbconvert.preprocessors import ExecutePreprocessor

TUTORIALS_DIR = Path(__file__).parent.parent / "tutorials"
TIMEOUT = 600  # 10 minutes per notebook


def get_notebooks():
    """Get all notebook files in the tutorials directory."""
    return sorted([f for f in TUTORIALS_DIR.glob("*.ipynb") if not f.name.startswith(".")])


def get_kernel_name():
    """Get the appropriate kernel name for the current Python version."""
    ksm = KernelSpecManager()
    kernel_name = f"python{sys.version_info.major}"

    # If python3 kernel not available, try ipykernel install
    if kernel_name not in ksm.find_kernel_specs():
        import subprocess

        subprocess.run([sys.executable, "-m", "ipykernel", "install", "--user"], check=True)

    return kernel_name


@pytest.mark.parametrize("notebook_path", get_notebooks())
def test_notebook_execution(notebook_path):
    """Test that a notebook executes without errors."""
    with open(notebook_path) as f:
        nb = nbformat.read(f, as_version=4)

    kernel_name = get_kernel_name()
    ep = ExecutePreprocessor(timeout=TIMEOUT, kernel_name=kernel_name)

    try:
        # Execute the notebook
        ep.preprocess(nb, {"metadata": {"path": str(notebook_path.parent)}})
    except Exception as e:
        pytest.fail(f"Error executing notebook {notebook_path.name}: {str(e)}")
