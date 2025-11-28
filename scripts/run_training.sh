#!/bin/bash

# Training-only script for Deep Malware APT Group Detection
# Runs only the training phase (assumes preprocessing is already done)

echo "=================================================="
echo "    Deep CNN For Malware APT GROUP IDENTIFICATION - Training"
echo "=================================================="

# Check if conda environment is activated
if [[ "$CONDA_DEFAULT_ENV" != "malware_detection" ]]; then
    echo "Please activate the malware_detection conda environment first:"
    echo "conda activate malware_detection"
    exit 1
fi

echo "Starting training at: $(date)"
echo ""

# Check if preprocessed data exists
if [ ! -f "models/processed_data.pkl" ]; then
    echo "Error: Preprocessed data not found!"
    echo "Please run preprocessing first: python 01_preprocess_data.py"
    exit 1
fi

# Run training
echo "=== Starting Model Training ==="
python 03_train_model.py
if [ $? -ne 0 ]; then
    echo "Error in model training!"
    exit 1
fi

echo "=================================================="
echo "    Training completed successfully!"
echo "    Completed at: $(date)"
echo "=================================================="