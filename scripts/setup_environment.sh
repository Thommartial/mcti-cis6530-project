#!/bin/bash

# Setup script for Deep  Malware MITRE group identification Project

echo "Setting up environment for Deep  Malware Classification..."

# Check if conda is installed and accessible
if ! command -v conda &> /dev/null; then
    echo "Error: Conda is not in PATH. Trying to initialize..."
    export PATH="/home/thom/miniconda3/bin:$PATH"
    if ! command -v conda &> /dev/null; then
        echo "Error: Conda not found at /home/thom/miniconda3/bin/conda"
        exit 1
    fi
fi

# Create conda environment with Python 3.10
echo "Creating conda environment 'cis6530'..."
conda create -n cis6530 python=3.10 -y

# Initialize conda for the current shell
eval "$(/home/thom/miniconda3/bin/conda shell.bash hook)"

# Activate environment
echo "Activating environment..."
conda activate cis6530

# Upgrade pip
echo "Upgrading pip..."
pip install --upgrade pip

# Install packages with loose dependencies
echo "Installing packages..."
pip install tensorflow scikit-learn pandas numpy matplotlib seaborn tqdm jupyter scipy

# Test the installation
echo "Testing installation..."
python -c "
import sys
import tensorflow as tf
import sklearn
import pandas as pd
import numpy as np
import matplotlib
import seaborn
import tqdm
import scipy

print('=== SUCCESS: All packages imported successfully! ===')
print('Python:', sys.version.split()[0])
print('TensorFlow:', tf.__version__)
print('Scikit-learn:', sklearn.__version__)
print('Pandas:', pd.__version__)
print('NumPy:', np.__version__)
"

echo ""
echo "=== Environment setup complete! ==="
echo "To activate the environment: conda activate cis6530"
echo "To run the pipeline: ./run_pipeline.sh"