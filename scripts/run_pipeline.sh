#!/bin/bash

# Master pipeline script for Deep Malware APT group Detection
# Runs the complete pipeline from preprocessing to evaluation

echo "=================================================="
echo "     CNN FOR APT MITRE GROUP IDENTIFICATION"
echo "=================================================="

# Check if conda environment is activated
if [[ "$CONDA_DEFAULT_ENV" != "cis6530" ]]; then
    echo "Please activate the cis6530 conda environment first:"
    echo "conda activate cis6530"
    exit 1
fi

# Create necessary directories
mkdir -p logs models img results

echo "Starting pipeline at: $(date)"
echo ""

# Step 1: Data Preprocessing
echo "=== STEP 1: Data Preprocessing ==="
python 01_preprocess_data.py
if [ $? -ne 0 ]; then
    echo "Error in data preprocessing!"
    exit 1
fi
echo ""

# Step 2: Model Building
echo "=== STEP 2: Model Building ==="
python 02_build_model.py
if [ $? -ne 0 ]; then
    echo "Error in model building!"
    exit 1
fi
echo ""

# Step 3: Model Training
echo "=== STEP 3: Model Training ==="
python 03_train_model.py
if [ $? -ne 0 ]; then
    echo "Error in model training!"
    exit 1
fi
echo ""

# Step 4: Model Evaluation
echo "=== STEP 4: Model Evaluation ==="
python 04_evaluate_model.py
if [ $? -ne 0 ]; then
    echo "Error in model evaluation!"
    exit 1
fi
echo ""

# Step 5: t-SNE Visualization
echo "=== STEP 5: t-SNE Visualization ==="
python 05_generate_tsne.py
if [ $? -ne 0 ]; then
    echo "Error in t-SNE visualization!"
    exit 1
fi
echo ""

echo "=================================================="
echo "    Pipeline completed successfully!"
echo "    Completed at: $(date)"
echo "=================================================="
echo ""
echo "Generated files:"
echo "- Model: models/best_model.h5"
echo "- Logs: logs/"
echo "- Plots: img/"
echo "- Results: results/classification_summary.txt"
echo ""
echo "To view results: cat results/classification_summary.txt"