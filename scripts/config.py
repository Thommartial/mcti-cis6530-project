"""
Configuration for Deep Malware APT Group Detection
Compatible with TensorFlow 2.20, Python 3.10
"""

import os
import sys
import warnings
from pathlib import Path

# Filter warnings
warnings.filterwarnings('ignore', category=FutureWarning)
warnings.filterwarnings('ignore', category=DeprecationWarning)

# Add scripts directory to path
SCRIPT_DIR = Path(__file__).parent
sys.path.append(str(SCRIPT_DIR))

# Project structure
PROJECT_ROOT = SCRIPT_DIR.parent
DATA_DIR = PROJECT_ROOT / "data" / "raw_opcode"
MODELS_DIR = PROJECT_ROOT / "models"
LOGS_DIR = PROJECT_ROOT / "logs"
IMG_DIR = PROJECT_ROOT / "img"
RESULTS_DIR = PROJECT_ROOT / "results"
REPORTS_DIR = PROJECT_ROOT / "reports"

# Create directories
for directory in [DATA_DIR, MODELS_DIR, LOGS_DIR, IMG_DIR, RESULTS_DIR, REPORTS_DIR]:
    directory.mkdir(exist_ok=True)

# Model hyperparameters - optimized for TensorFlow 2.20
# In the MODEL_CONFIG section, remove the fixed num_classes:
MODEL_CONFIG = {
    'embedding_dim': 8,
    'num_filters': 64,
    'filter_length': 8,
    'hidden_units': 16,
    # 'num_classes': 25,  # REMOVE THIS - will be determined dynamically
    'max_sequence_length': 5000,
    'vocab_size': 218,
    'batch_size': 16,
    'epochs': 30,
    'learning_rate': 0.01,
    'validation_split': 0.1,
    'test_split': 0.3
}

# Training configuration for TF 2.20
TRAINING_CONFIG = {
    'early_stopping_patience': 8,
    'reduce_lr_patience': 5,
    'class_weight_method': 'balanced'
}

# File patterns
OPCODE_FILE_PATTERN = "*.opcode"
MODEL_SAVE_PATH = MODELS_DIR / "malware_detection_model.h5"
CLASS_NAMES_SAVE_PATH = MODELS_DIR / "class_names.pkl"

# Logging configuration
LOG_CONFIG = {
    'disable_existing_loggers': False,
    'formatters': {
        'standard': {
            'format': '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        },
    },
    'handlers': {
        'file_preprocess': {
            'class': 'logging.FileHandler',
            'filename': str(LOGS_DIR / 'preprocessing.log'),
            'formatter': 'standard',
            'level': 'INFO'
        },
    },
    'loggers': {
        'preprocess': {
            'handlers': ['file_preprocess'],
            'level': 'INFO',
            'propagate': False
        },
    }
}