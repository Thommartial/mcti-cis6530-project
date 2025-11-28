#!/usr/bin/env python3
"""
Advanced Model Training - Building on paper concepts but modified for multi-class APT detection
"""

import os
import sys
import logging
import pickle
import numpy as np
import tensorflow as tf
from tensorflow.keras.models import Model
from tensorflow.keras.layers import (
    Input, Embedding, Conv1D, GlobalMaxPooling1D, GlobalAveragePooling1D,
    Dense, Dropout, BatchNormalization, concatenate, LSTM, Bidirectional
)
from tensorflow.keras.optimizers import Adam
from tensorflow.keras.callbacks import (
    EarlyStopping, ReduceLROnPlateau, ModelCheckpoint, CSVLogger
)
from tensorflow.keras.regularizers import l1_l2
from sklearn.utils.class_weight import compute_class_weight
import matplotlib.pyplot as plt
import seaborn as sns

sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import config

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(config.LOGS_DIR / 'advanced_training.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('advanced_training')

def build_advanced_model(vocab_size, num_classes, sequence_length):
    """Advanced architecture combining CNN, LSTM, and attention concepts"""
    logger.info("Building advanced multi-scale architecture...")
    
    # Input layer
    input_layer = Input(shape=(sequence_length,), name='input')
    
    # Enhanced embedding with dropout
    embedding = Embedding(
        input_dim=vocab_size,
        output_dim=128,  # Larger embedding for richer representations
        input_length=sequence_length,
        name='embedding'
    )(input_layer)
    
    embedding = Dropout(0.2)(embedding)
    
    # Multi-scale convolutional branches (capture different n-gram patterns)
    conv_branches = []
    
    # Short-range patterns (like 3-grams)
    conv1 = Conv1D(128, 3, activation='relu', padding='same', name='conv_3')(embedding)
    conv1 = BatchNormalization()(conv1)
    conv_branches.append(conv1)
    
    # Medium-range patterns (like 5-grams) 
    conv2 = Conv1D(128, 5, activation='relu', padding='same', name='conv_5')(embedding)
    conv2 = BatchNormalization()(conv2)
    conv_branches.append(conv2)
    
    # Long-range patterns (like 8-grams - paper's original)
    conv3 = Conv1D(128, 8, activation='relu', padding='same', name='conv_8')(embedding)
    conv3 = BatchNormalization()(conv3)
    conv_branches.append(conv3)
    
    # Very long-range patterns
    conv4 = Conv1D(128, 12, activation='relu', padding='same', name='conv_12')(embedding)
    conv4 = BatchNormalization()(conv4)
    conv_branches.append(conv4)
    
    # Concatenate all convolutional branches
    concatenated = concatenate(conv_branches, name='multi_scale_concat')
    
    # Bidirectional LSTM for sequence modeling
    lstm_out = Bidirectional(
        LSTM(64, return_sequences=True, dropout=0.2, recurrent_dropout=0.2),
        name='bilstm'
    )(concatenated)
    
    # Dual pooling strategy
    max_pool = GlobalMaxPooling1D(name='global_max_pool')(lstm_out)
    avg_pool = GlobalAveragePooling1D(name='global_avg_pool')(lstm_out)
    
    # Combine pooling strategies
    pooled = concatenate([max_pool, avg_pool], name='dual_pooling')
    
    # Deep classifier with regularization
    x = Dense(256, activation='relu', kernel_regularizer=l1_l2(0.01, 0.01), name='dense_1')(pooled)
    x = BatchNormalization()(x)
    x = Dropout(0.5)(x)
    
    x = Dense(128, activation='relu', kernel_regularizer=l1_l2(0.01, 0.01), name='dense_2')(x)
    x = BatchNormalization()(x)
    x = Dropout(0.4)(x)
    
    x = Dense(64, activation='relu', kernel_regularizer=l1_l2(0.01, 0.01), name='dense_3')(x)
    x = BatchNormalization()(x)
    x = Dropout(0.3)(x)
    
    # Output layer
    output = Dense(num_classes, activation='softmax', name='output')(x)
    
    model = Model(inputs=input_layer, outputs=output, name='advanced_apt_detector')
    
    # Advanced optimizer with gradient clipping
    optimizer = Adam(
        learning_rate=0.001,
        beta_1=0.9,
        beta_2=0.999,
        clipnorm=1.0  # Gradient clipping for stability
    )
    
    model.compile(
        optimizer=optimizer,
        loss='categorical_crossentropy',
        metrics=['accuracy', 'precision', 'recall']
    )
    
    logger.info("Advanced model built successfully!")
    return model

def apply_smart_augmentation(X, y, y_int, augmentation_strategy='balanced'):
    """Smart data augmentation focusing on minority classes"""
    logger.info("Applying smart data augmentation...")
    
    class_counts = np.bincount(y_int)
    target_samples = np.median(class_counts[class_counts > 0])  # Target median class size
    
    augmented_X = [X]
    augmented_y = [y]
    
    for class_idx in range(len(class_counts)):
        current_count = class_counts[class_idx]
        
        if current_count < target_samples and current_count > 0:
            # Calculate how many samples to add
            needed = int(target_samples - current_count)
            
            if needed > 0:
                class_mask = (y_int == class_idx)
                class_samples_X = X[class_mask]
                class_samples_y = y[class_mask]
                
                # Add augmented samples with slight variations
                for i in range(min(needed, len(class_samples_X) * 3)):  # Limit augmentation
                    # Select a random sample from this class
                    idx = np.random.randint(0, len(class_samples_X))
                    sample = class_samples_X[idx].copy()
                    
                    # Apply mild augmentation - small random masking
                    mask_indices = np.random.choice(
                        sequence_length, 
                        size=int(sequence_length * 0.05),  # Mask 5% of sequence
                        replace=False
                    )
                    sample[mask_indices] = 0  # Mask with padding token
                    
                    augmented_X.append(sample.reshape(1, -1))
                    augmented_y.append(class_samples_y[idx].reshape(1, -1))
                
                logger.info(f"  Class {class_idx}: {current_count} → ~{current_count + needed} samples")
    
    # Combine all data
    X_augmented = np.vstack(augmented_X)
    y_augmented = np.vstack(augmented_y)
    
    logger.info(f"Augmentation: {len(X)} → {len(X_augmented)} samples")
    return X_augmented, y_augmented

def create_advanced_callbacks():
    """Advanced callback configuration"""
    return [
        EarlyStopping(
            monitor='val_accuracy',
            patience=25,  # Very patient for complex model
            restore_best_weights=True,
            verbose=1,
            mode='max',
            min_delta=0.001
        ),
        ReduceLROnPlateau(
            monitor='val_accuracy',
            factor=0.5,
            patience=12,
            min_lr=1e-7,
            verbose=1,
            mode='max',
            min_delta=0.001
        ),
        ModelCheckpoint(
            filepath=config.MODELS_DIR / 'advanced_best_model.h5',
            monitor='val_accuracy',
            save_best_only=True,
            mode='max',
            verbose=1
        ),
        CSVLogger(
            filename=config.LOGS_DIR / 'advanced_training_history.csv',
            separator=',',
            append=False
        )
    ]

def main():
    """Main advanced training function"""
    try:
        logger.info("Starting advanced model training for APT group classification...")
        
        # Load processed data
        with open(config.MODELS_DIR / 'processed_data.pkl', 'rb') as f:
            processed_data = pickle.load(f)
        
        X_train = processed_data['X_train']
        X_val = processed_data['X_val']
        y_train = processed_data['y_train']
        y_val = processed_data['y_val']
        y_train_int = processed_data['y_int_train']
        vocab_size = processed_data['vocab_size']
        num_classes = processed_data['num_classes']
        sequence_length = X_train.shape[1]
        
        logger.info(f"Training on {num_classes} APT groups")
        logger.info(f"Initial data: {X_train.shape[0]} train, {X_val.shape[0]} val")
        
        # Smart data augmentation
        X_train_aug, y_train_aug = apply_smart_augmentation(X_train, y_train, y_train_int)
        
        # Compute advanced class weights
        class_weights = compute_class_weight(
            class_weight='balanced',
            classes=np.unique(y_train_int),
            y=y_train_int
        )
        class_weight_dict = {i: weight for i, weight in enumerate(class_weights)}
        logger.info("Class weights computed for imbalance")
        
        # Build advanced model
        model = build_advanced_model(vocab_size, num_classes, sequence_length)
        model.summary(print_fn=logger.info)
        
        # Advanced training
        logger.info("Starting advanced training...")
        history = model.fit(
            X_train_aug, y_train_aug,
            batch_size=32,
            epochs=200,  # More epochs for complex model
            validation_data=(X_val, y_val),
            class_weight=class_weight_dict,
            callbacks=create_advanced_callbacks(),
            verbose=1,
            shuffle=True
        )
        
        # Enhanced plotting
        fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 10))
        
        # Loss
        ax1.plot(history.history['loss'], label='Training Loss')
        ax1.plot(history.history['val_loss'], label='Validation Loss')
        ax1.set_title('Model Loss')
        ax1.legend()
        ax1.grid(True, alpha=0.3)
        
        # Accuracy
        ax2.plot(history.history['accuracy'], label='Training Accuracy')
        ax2.plot(history.history['val_accuracy'], label='Validation Accuracy')
        ax2.set_title('Model Accuracy')
        ax2.legend()
        ax2.grid(True, alpha=0.3)
        
        # Precision
        ax3.plot(history.history['precision'], label='Training Precision')
        ax3.plot(history.history['val_precision'], label='Validation Precision')
        ax3.set_title('Model Precision')
        ax3.legend()
        ax3.grid(True, alpha=0.3)
        
        # Recall
        ax4.plot(history.history['recall'], label='Training Recall')
        ax4.plot(history.history['val_recall'], label='Validation Recall')
        ax4.set_title('Model Recall')
        ax4.legend()
        ax4.grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(config.IMG_DIR / 'advanced_training_history.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        # Save model
        model.save(config.MODELS_DIR / 'advanced_trained_model.h5')
        
        # Comprehensive results analysis
        best_epoch = np.argmax(history.history['val_accuracy'])
        best_val_acc = history.history['val_accuracy'][best_epoch]
        best_val_precision = history.history['val_precision'][best_epoch]
        best_val_recall = history.history['val_recall'][best_epoch]
        
        logger.info(f"\n🎯 ADVANCED TRAINING RESULTS")
        logger.info(f"Best Validation Accuracy: {best_val_acc:.4f} (epoch {best_epoch + 1})")
        logger.info(f"Best Validation Precision: {best_val_precision:.4f}")
        logger.info(f"Best Validation Recall: {best_val_recall:.4f}")
        logger.info(f"Final Training Accuracy: {history.history['accuracy'][-1]:.4f}")
        
        # Performance assessment
        random_baseline = 1.0 / num_classes
        improvement_over_random = (best_val_acc - random_baseline) / random_baseline
        
        logger.info(f"Random baseline: {random_baseline:.4f}")
        logger.info(f"Improvement over random: {improvement_over_random:.1%}")
        
        if best_val_acc > 0.5:
            logger.info("🚀 EXCELLENT: Model learned strong patterns!")
        elif best_val_acc > 0.3:
            logger.info("✅ GOOD: Model learned meaningful patterns")
        elif best_val_acc > 0.15:
            logger.info("⚠️ MODEST: Model shows some learning")
        else:
            logger.info("🔍 DIFFICULT: Problem is very challenging")
            
        logger.info("Advanced training completed!")
        
    except Exception as e:
        logger.error(f"Error in advanced training: {e}")
        raise

if __name__ == "__main__":
    main()