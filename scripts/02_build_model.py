#!/usr/bin/env python3
"""
Model Building Script for Deep Malware MITRE group Detection
Compatible with TensorFlow 2.20 and dynamic class handling
"""

import os
import sys
import logging
import pickle
import tensorflow as tf
from tensorflow.keras.models import Model
from tensorflow.keras.layers import (
    Input, Embedding, Conv1D, GlobalMaxPooling1D, 
    Dense, Dropout, BatchNormalization
)
from tensorflow.keras.optimizers import RMSprop
from tensorflow.keras.regularizers import l2

# Add config to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import config

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(config.LOGS_DIR / 'model_building.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('model_building')

# Set TensorFlow logging level
tf.get_logger().setLevel('ERROR')

class MalwareDetectionModel:
    def __init__(self, vocab_size, num_classes, sequence_length):
        self.vocab_size = vocab_size
        self.num_classes = num_classes
        self.sequence_length = sequence_length
        self.model = None
    
    def build_model(self):
        """Build the CNN model compatible with TF 2.20"""
        logger.info("Building malware detection model...")
        
        try:
            # Input layer
            input_layer = Input(shape=(self.sequence_length,), name='input')
            
            # Embedding layer
            embedding = Embedding(
                input_dim=self.vocab_size,
                output_dim=config.MODEL_CONFIG['embedding_dim'],
                input_length=self.sequence_length,
                name='embedding'
            )(input_layer)
            
            # Convolutional layer
            conv1 = Conv1D(
                filters=config.MODEL_CONFIG['num_filters'],
                kernel_size=config.MODEL_CONFIG['filter_length'],
                activation='relu',
                padding='same',
                kernel_regularizer=l2(0.001),
                name='convolutional'
            )(embedding)
            
            # Batch normalization
            bn1 = BatchNormalization(name='batch_norm')(conv1)
            
            # Global max pooling
            pooling = GlobalMaxPooling1D(name='global_max_pooling')(bn1)
            
            # Hidden fully connected layer
            hidden = Dense(
                config.MODEL_CONFIG['hidden_units'],
                activation='relu',
                kernel_regularizer=l2(0.001),
                name='hidden_dense'
            )(pooling)
            
            # Dropout for regularization
            dropout = Dropout(0.5, name='dropout')(hidden)
            
            # Output layer - uses dynamic num_classes
            output = Dense(
                self.num_classes,
                activation='softmax',
                name='output'
            )(dropout)
            
            # Create model
            self.model = Model(inputs=input_layer, outputs=output, name='malware_detection_cnn')
            
            # Compile model with TF 2.20 compatible settings
            optimizer = RMSprop(learning_rate=config.MODEL_CONFIG['learning_rate'])
            
            self.model.compile(
                optimizer=optimizer,
                loss='categorical_crossentropy',
                metrics=['accuracy', 'precision', 'recall']
            )
            
            logger.info("Model built and compiled successfully!")
            return self.model
            
        except Exception as e:
            logger.error(f"Error building model: {e}")
            raise
    
    def print_model_summary(self):
        """Print model architecture summary"""
        if self.model:
            self.model.summary(print_fn=logger.info)
    
    def save_model_architecture(self):
        """Save model architecture diagram"""
        try:
            # Try to plot model architecture
            tf.keras.utils.plot_model(
                self.model,
                to_file=config.IMG_DIR / 'model_architecture.png',
                show_shapes=True,
                show_layer_names=True,
                dpi=150
            )
            logger.info("Model architecture diagram saved")
        except Exception as e:
            logger.warning(f"Could not save model diagram: {e}")
            logger.info("This is not critical - continuing without diagram")

def main():
    """Main model building function"""
    try:
        logger.info("Starting model building...")
        
        # Load processed data to get dimensions
        try:
            with open(config.MODELS_DIR / 'processed_data.pkl', 'rb') as f:
                processed_data = pickle.load(f)
            
            vocab_size = processed_data['vocab_size']
            num_classes = processed_data['num_classes']  # Dynamic from preprocessing
            sequence_length = processed_data['X_train'].shape[1]
            
            logger.info(f"Loaded processed data: {len(processed_data['X_train'])} training samples")
            logger.info(f"Class distribution: {processed_data.get('class_distribution', 'Not available')}")
            
        except FileNotFoundError:
            logger.error("Processed data not found! Please run preprocessing first.")
            logger.info("Run: python 01_preprocess_data.py")
            return
        except Exception as e:
            logger.error(f"Error loading processed data: {e}")
            return
        
        logger.info(f"Model parameters: vocab_size={vocab_size}, "
                   f"num_classes={num_classes}, sequence_length={sequence_length}")
        
        # Validate parameters
        if num_classes < 2:
            logger.error(f"Invalid number of classes: {num_classes}. Need at least 2 classes.")
            return
        
        if vocab_size < 10:
            logger.warning(f"Very small vocabulary size: {vocab_size}")
        
        # Build model
        model_builder = MalwareDetectionModel(vocab_size, num_classes, sequence_length)
        model = model_builder.build_model()
        
        # Print summary
        model_builder.print_model_summary()
        
        # Save model architecture diagram
        model_builder.save_model_architecture()
        
        # Save initial model
        try:
            model.save(config.MODEL_SAVE_PATH)
            logger.info(f"Model saved to {config.MODEL_SAVE_PATH}")
        except Exception as e:
            logger.error(f"Error saving model: {e}")
            # Try alternative save method
            try:
                model.save(config.MODELS_DIR / 'malware_model.keras')
                logger.info("Model saved as .keras format")
            except Exception as e2:
                logger.error(f"Alternative save also failed: {e2}")
                raise
        
        # Print model info for verification
        logger.info("\n=== MODEL INFORMATION ===")
        logger.info(f"Input shape: {model.input_shape}")
        logger.info(f"Output shape: {model.output_shape}")
        logger.info(f"Number of parameters: {model.count_params():,}")
        logger.info(f"Number of layers: {len(model.layers)}")
        
        # List all layers
        logger.info("\nModel layers:")
        for i, layer in enumerate(model.layers):
            logger.info(f"  {i+1:2d}. {layer.name:20} {type(layer).__name__:15} {layer.output_shape}")
        
        logger.info("Model building completed successfully!")
        
    except Exception as e:
        logger.error(f"Error in model building: {e}")
        logger.info("This might be due to:")
        logger.info("1. Missing processed data - run preprocessing first")
        logger.info("2. Memory issues - try reducing sequence length in config")
        logger.info("3. Package compatibility issues")
        raise

if __name__ == "__main__":
    main()