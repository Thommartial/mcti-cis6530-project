#!/usr/bin/env python3
"""
Baseline Model Comparison Script
Compares CNN performance against traditional ML classifiers
"""
import sys
import os
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import logging
import pickle
import time
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.ensemble import RandomForestClassifier
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn.neighbors import KNeighborsClassifier
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score
from sklearn.metrics import classification_report, confusion_matrix
import tensorflow as tf
import config

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(config.LOGS_DIR / 'baseline_comparison.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('baseline')

class BaselineComparator:
    def __init__(self, X_train, y_train, X_test, y_test, class_names):
        self.X_train = X_train
        self.y_train = y_train
        self.X_test = X_test
        self.y_test = y_test
        self.class_names = class_names
        self.results = {}
        
    def evaluate_model(self, model, model_name, training_time):
        """Evaluate a model and return comprehensive metrics"""
        logger.info(f"Evaluating {model_name}...")
        
        # Predictions
        start_time = time.time()
        y_pred = model.predict(self.X_test)
        inference_time = time.time() - start_time
        
        # Calculate metrics
        accuracy = accuracy_score(self.y_test, y_pred)
        precision_macro = precision_score(self.y_test, y_pred, average='macro', zero_division=0)
        recall_macro = recall_score(self.y_test, y_pred, average='macro', zero_division=0)
        f1_macro = f1_score(self.y_test, y_pred, average='macro', zero_division=0)
        precision_weighted = precision_score(self.y_test, y_pred, average='weighted', zero_division=0)
        recall_weighted = recall_score(self.y_test, y_pred, average='weighted', zero_division=0)
        f1_weighted = f1_score(self.y_test, y_pred, average='weighted', zero_division=0)
        
        # Store results
        self.results[model_name] = {
            'accuracy': accuracy,
            'precision_macro': precision_macro,
            'recall_macro': recall_macro,
            'f1_macro': f1_macro,
            'precision_weighted': precision_weighted,
            'recall_weighted': recall_weighted,
            'f1_weighted': f1_weighted,
            'training_time': training_time,
            'inference_time': inference_time,
            'model': model
        }
        
        logger.info(f"{model_name} - Accuracy: {accuracy:.4f}, F1 Macro: {f1_macro:.4f}")
        
        return self.results[model_name]
    
    def train_decision_tree(self):
        """Train and evaluate Decision Tree classifier"""
        logger.info("Training Decision Tree...")
        start_time = time.time()
        
        model = DecisionTreeClassifier(
            random_state=42,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            class_weight='balanced'
        )
        model.fit(self.X_train, self.y_train)
        training_time = time.time() - start_time
        
        return self.evaluate_model(model, "Decision Tree", training_time)
    
    def train_random_forest(self):
        """Train and evaluate Random Forest classifier"""
        logger.info("Training Random Forest...")
        start_time = time.time()
        
        model = RandomForestClassifier(
            n_estimators=100,
            random_state=42,
            max_depth=15,
            min_samples_split=5,
            min_samples_leaf=2,
            class_weight='balanced_subsample',
            n_jobs=-1
        )
        model.fit(self.X_train, self.y_train)
        training_time = time.time() - start_time
        
        return self.evaluate_model(model, "Random Forest", training_time)
    
    def train_svm(self):
        """Train and evaluate SVM classifier"""
        logger.info("Training SVM...")
        start_time = time.time()
        
        # Use linear SVM for efficiency with high-dimensional data
        model = SVC(
            kernel='linear',
            random_state=42,
            class_weight='balanced',
            probability=False
        )
        model.fit(self.X_train, self.y_train)
        training_time = time.time() - start_time
        
        return self.evaluate_model(model, "Linear SVM", training_time)
    
    def train_knn(self, k=3):
        """Train and evaluate K-Nearest Neighbors classifier"""
        logger.info(f"Training KNN (k={k})...")
        start_time = time.time()
        
        model = KNeighborsClassifier(
            n_neighbors=k,
            weights='distance',
            n_jobs=-1
        )
        model.fit(self.X_train, self.y_train)
        training_time = time.time() - start_time
        
        return self.evaluate_model(model, f"KNN (k={k})", training_time)
    
    def evaluate_cnn(self):
        """Evaluate the pre-trained CNN model"""
        logger.info("Evaluating CNN model...")
        
        # Load the trained CNN model
        model_path = config.MODELS_DIR / 'best_model.h5'
        if not model_path.exists():
            logger.error(f"CNN model not found: {model_path}")
            return None
            
        model = tf.keras.models.load_model(model_path)
        
        # For CNN, we consider training time as the time recorded during training
        # Use a placeholder training time (you might want to load the actual training time)
        training_time = 300  # Placeholder - adjust based on your actual training time
        
        # Predict with CNN
        start_time = time.time()
        y_pred_proba = model.predict(self.X_test, verbose=0)
        y_pred = np.argmax(y_pred_proba, axis=1)
        inference_time = time.time() - start_time
        
        # Calculate metrics
        accuracy = accuracy_score(self.y_test, y_pred)
        precision_macro = precision_score(self.y_test, y_pred, average='macro', zero_division=0)
        recall_macro = recall_score(self.y_test, y_pred, average='macro', zero_division=0)
        f1_macro = f1_score(self.y_test, y_pred, average='macro', zero_division=0)
        precision_weighted = precision_score(self.y_test, y_pred, average='weighted', zero_division=0)
        recall_weighted = recall_score(self.y_test, y_pred, average='weighted', zero_division=0)
        f1_weighted = f1_score(self.y_test, y_pred, average='weighted', zero_division=0)
        
        # Store results
        self.results["CNN (Advanced)"] = {
            'accuracy': accuracy,
            'precision_macro': precision_macro,
            'recall_macro': recall_macro,
            'f1_macro': f1_macro,
            'precision_weighted': precision_weighted,
            'recall_weighted': recall_weighted,
            'f1_weighted': f1_weighted,
            'training_time': training_time,
            'inference_time': inference_time,
            'model': model
        }
        
        logger.info(f"CNN - Accuracy: {accuracy:.4f}, F1 Macro: {f1_macro:.4f}")
        
        return self.results["CNN (Advanced)"]
    
    def create_comparison_table(self):
        """Create a comprehensive comparison table"""
        logger.info("Creating comparison table...")
        
        # Prepare data for table
        comparison_data = []
        for model_name, metrics in self.results.items():
            comparison_data.append({
                'Model': model_name,
                'Accuracy': f"{metrics['accuracy']:.4f}",
                'Precision (Macro)': f"{metrics['precision_macro']:.4f}",
                'Recall (Macro)': f"{metrics['recall_macro']:.4f}",
                'F1-Score (Macro)': f"{metrics['f1_macro']:.4f}",
                'Precision (Weighted)': f"{metrics['precision_weighted']:.4f}",
                'Recall (Weighted)': f"{metrics['recall_weighted']:.4f}",
                'F1-Score (Weighted)': f"{metrics['f1_weighted']:.4f}",
                'Training Time (s)': f"{metrics['training_time']:.2f}",
                'Inference Time (s)': f"{metrics['inference_time']:.4f}"
            })
        
        # Create DataFrame
        df = pd.DataFrame(comparison_data)
        
        # Save to CSV
        csv_path = config.RESULTS_DIR / 'baseline_comparison.csv'
        df.to_csv(csv_path, index=False)
        logger.info(f"Comparison table saved: {csv_path}")
        
        return df
    
    def plot_comparison(self):
        """Create visualization comparing model performance"""
        logger.info("Creating performance comparison plots...")
        
        # Set style
        plt.style.use('default')
        sns.set_palette("husl")
        
        # Create subplots
        fig, axes = plt.subplots(2, 2, figsize=(15, 12))
        axes = axes.flatten()
        
        # Plot 1: Accuracy and F1-Score Comparison
        models = list(self.results.keys())
        accuracy_scores = [self.results[m]['accuracy'] for m in models]
        f1_scores = [self.results[m]['f1_weighted'] for m in models]
        
        x = np.arange(len(models))
        width = 0.35
        
        axes[0].bar(x - width/2, accuracy_scores, width, label='Accuracy', alpha=0.8)
        axes[0].bar(x + width/2, f1_scores, width, label='F1-Score (Weighted)', alpha=0.8)
        axes[0].set_xlabel('Models')
        axes[0].set_ylabel('Scores')
        axes[0].set_title('Model Performance: Accuracy vs F1-Score')
        axes[0].set_xticks(x)
        axes[0].set_xticklabels(models, rotation=45, ha='right')
        axes[0].legend()
        axes[0].grid(True, alpha=0.3)
        
        # Plot 2: Precision and Recall (Macro)
        precision_scores = [self.results[m]['precision_macro'] for m in models]
        recall_scores = [self.results[m]['recall_macro'] for m in models]
        
        axes[1].bar(x - width/2, precision_scores, width, label='Precision (Macro)', alpha=0.8)
        axes[1].bar(x + width/2, recall_scores, width, label='Recall (Macro)', alpha=0.8)
        axes[1].set_xlabel('Models')
        axes[1].set_ylabel('Scores')
        axes[1].set_title('Model Performance: Precision vs Recall (Macro)')
        axes[1].set_xticks(x)
        axes[1].set_xticklabels(models, rotation=45, ha='right')
        axes[1].legend()
        axes[1].grid(True, alpha=0.3)
        
        # Plot 3: Training Time Comparison
        training_times = [self.results[m]['training_time'] for m in models]
        
        axes[2].bar(x, training_times, color='orange', alpha=0.8)
        axes[2].set_xlabel('Models')
        axes[2].set_ylabel('Time (seconds)')
        axes[2].set_title('Model Training Time Comparison')
        axes[2].set_xticks(x)
        axes[2].set_xticklabels(models, rotation=45, ha='right')
        axes[2].grid(True, alpha=0.3)
        
        # Plot 4: Inference Time Comparison
        inference_times = [self.results[m]['inference_time'] for m in models]
        
        axes[3].bar(x, inference_times, color='green', alpha=0.8)
        axes[3].set_xlabel('Models')
        axes[3].set_ylabel('Time (seconds)')
        axes[3].set_title('Model Inference Time Comparison')
        axes[3].set_xticks(x)
        axes[3].set_xticklabels(models, rotation=45, ha='right')
        axes[3].grid(True, alpha=0.3)
        
        plt.tight_layout()
        plt.savefig(config.IMG_DIR / 'baseline_comparison.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        logger.info("Comparison plots saved")
    
    def run_comprehensive_comparison(self):
        """Run comprehensive comparison of all models"""
        logger.info("Starting comprehensive baseline comparison...")
        
        # Evaluate all models
        self.train_decision_tree()
        self.train_random_forest()
        self.train_svm()
        self.train_knn(k=3)
        self.train_knn(k=5)
        self.evaluate_cnn()
        
        # Generate comparison outputs
        comparison_table = self.create_comparison_table()
        self.plot_comparison()
        
        # Print summary
        logger.info("\n" + "="*60)
        logger.info("COMPARISON SUMMARY")
        logger.info("="*60)
        for model_name, metrics in self.results.items():
            logger.info(f"{model_name:15} | Acc: {metrics['accuracy']:.4f} | "
                       f"F1-Macro: {metrics['f1_macro']:.4f} | "
                       f"Train: {metrics['training_time']:.2f}s")
        
        return self.results

def main():
    """Main baseline comparison function"""
    try:
        logger.info("Starting baseline model comparison...")
        
        # Load processed data
        with open(config.MODELS_DIR / 'processed_data.pkl', 'rb') as f:
            processed_data = pickle.load(f)
        
        # Load class mapping
        with open(config.MODELS_DIR / 'class_mapping.pkl', 'rb') as f:
            class_mapping = pickle.load(f)
        
        # Prepare data for traditional ML models
        # For traditional ML, we need to reshape the data from sequences to feature vectors
        X_train = processed_data['X_train']
        X_test = processed_data['X_test']
        y_train = processed_data['y_int_train']
        y_test = processed_data['y_int_test']
        
        # Reshape for traditional ML (flatten sequences)
        X_train_flat = X_train.reshape(X_train.shape[0], -1)
        X_test_flat = X_test.reshape(X_test.shape[0], -1)
        
        logger.info(f"Training data shape: {X_train_flat.shape}")
        logger.info(f"Test data shape: {X_test_flat.shape}")
        logger.info(f"Number of classes: {len(class_mapping['int_to_class'])}")
        
        # Create comparator
        comparator = BaselineComparator(
            X_train_flat, y_train,
            X_test_flat, y_test,
            class_names=list(class_mapping['int_to_class'].values())
        )
        
        # Run comprehensive comparison
        results = comparator.run_comprehensive_comparison()
        
        logger.info("Baseline comparison completed successfully!")
        
        return results
        
    except Exception as e:
        logger.error(f"Error in baseline comparison: {e}")
        raise

if __name__ == "__main__":
    main()