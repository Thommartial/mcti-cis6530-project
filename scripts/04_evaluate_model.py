#!/usr/bin/env python3
"""
Model Evaluation Script for Deep Malware APT Group Identification
Comprehensive evaluation with metrics, confusion matrix, and reports
"""

import sys
import os
# Add the scripts directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import logging
import pickle
import numpy as np
import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.metrics import (
    classification_report, confusion_matrix, 
    accuracy_score, precision_recall_fscore_support
)
from sklearn.preprocessing import label_binarize
import tensorflow as tf
import config

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(config.LOGS_DIR / 'evaluation.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('evaluation')

class ModelEvaluator:
    def __init__(self, model, X_test, y_test, y_int_test, int_to_class, filenames=None):
        self.model = model
        self.X_test = X_test
        self.y_test = y_test
        self.y_int_test = y_int_test
        self.int_to_class = int_to_class
        self.filenames = filenames or []
        
        # Results storage
        self.predictions = None
        self.predicted_classes = None
        self.true_classes = None
        self.metrics = {}
    
    def make_predictions(self):
        """Generate model predictions"""
        logger.info("Generating predictions...")
        
        self.predictions = self.model.predict(self.X_test, verbose=0)
        self.predicted_classes = np.argmax(self.predictions, axis=1)
        self.true_classes = self.y_int_test
        
        logger.info(f"Predictions shape: {self.predictions.shape}")
    
    def calculate_metrics(self):
        """Calculate comprehensive evaluation metrics"""
        logger.info("Calculating evaluation metrics...")
        
        # Basic metrics
        accuracy = accuracy_score(self.true_classes, self.predicted_classes)
        
        # Per-class metrics
        precision, recall, f1, support = precision_recall_fscore_support(
            self.true_classes, self.predicted_classes, average=None
        )
        
        # Macro averages
        precision_macro, recall_macro, f1_macro, _ = precision_recall_fscore_support(
            self.true_classes, self.predicted_classes, average='macro'
        )
        
        # Weighted averages
        precision_weighted, recall_weighted, f1_weighted, _ = precision_recall_fscore_support(
            self.true_classes, self.predicted_classes, average='weighted'
        )
        
        # Store metrics
        self.metrics = {
            'accuracy': accuracy,
            'precision_macro': precision_macro,
            'recall_macro': recall_macro,
            'f1_macro': f1_macro,
            'precision_weighted': precision_weighted,
            'recall_weighted': recall_weighted,
            'f1_weighted': f1_weighted,
            'per_class': {
                'precision': precision,
                'recall': recall,
                'f1': f1,
                'support': support
            }
        }
        
        return self.metrics
    
    def plot_confusion_matrix(self):
        """Plot professional confusion matrix"""
        logger.info("Plotting confusion matrix...")
        
        # Calculate confusion matrix
        cm = confusion_matrix(self.true_classes, self.predicted_classes)
        
        # Create figure
        plt.figure(figsize=(12, 10))
        
        # Get class labels
        class_labels = [self.int_to_class[i] for i in range(len(self.int_to_class))]
        
        # Create heatmap
        sns.heatmap(
            cm, 
            annot=True, 
            fmt='d',
            cmap='Blues',
            xticklabels=class_labels,
            yticklabels=class_labels,
            cbar_kws={'shrink': 0.8}
        )
        
        plt.title('Confusion Matrix - Malware APT Group Classification', 
                 fontsize=16, fontweight='bold', pad=20)
        plt.xlabel('Predicted Label', fontsize=12, fontweight='bold')
        plt.ylabel('True Label', fontsize=12, fontweight='bold')
        plt.xticks(rotation=45, ha='right')
        plt.yticks(rotation=0)
        
        plt.tight_layout()
        plt.savefig(config.IMG_DIR / 'confusion_matrix.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        logger.info("Confusion matrix plot saved")
        
        return cm
    
    def plot_metrics_comparison(self):
        """Plot comparison of different metrics"""
        logger.info("Plotting metrics comparison...")
        
        metrics = ['precision', 'recall', 'f1']
        macro_scores = [
            self.metrics['precision_macro'],
            self.metrics['recall_macro'],
            self.metrics['f1_macro']
        ]
        weighted_scores = [
            self.metrics['precision_weighted'],
            self.metrics['recall_weighted'],
            self.metrics['f1_weighted']
        ]
        
        x = np.arange(len(metrics))
        width = 0.35
        
        fig, ax = plt.subplots(figsize=(10, 6))
        rects1 = ax.bar(x - width/2, macro_scores, width, label='Macro Average', alpha=0.8)
        rects2 = ax.bar(x + width/2, weighted_scores, width, label='Weighted Average', alpha=0.8)
        
        ax.set_xlabel('Metrics', fontsize=12, fontweight='bold')
        ax.set_ylabel('Scores', fontsize=12, fontweight='bold')
        ax.set_title('Model Performance Metrics Comparison', fontsize=14, fontweight='bold')
        ax.set_xticks(x)
        ax.set_xticklabels(metrics)
        ax.legend()
        ax.grid(True, alpha=0.3, axis='y')
        
        # Add value labels on bars
        for rect in rects1 + rects2:
            height = rect.get_height()
            ax.annotate(f'{height:.3f}',
                       xy=(rect.get_x() + rect.get_width() / 2, height),
                       xytext=(0, 3),
                       textcoords="offset points",
                       ha='center', va='bottom', fontsize=10)
        
        plt.tight_layout()
        plt.savefig(config.IMG_DIR / 'metrics_comparison.png', dpi=300, bbox_inches='tight')
        plt.close()
        
        logger.info("Metrics comparison plot saved")
    
    def generate_classification_report(self):
        """Generate detailed classification report"""
        logger.info("Generating classification report...")
        
        class_labels = [self.int_to_class[i] for i in range(len(self.int_to_class))]
        
        report = classification_report(
            self.true_classes, 
            self.predicted_classes,
            target_names=class_labels,
            output_dict=True
        )
        
        # Convert to DataFrame for better formatting
        report_df = pd.DataFrame(report).transpose()
        
        return report_df
    
    def save_results(self, cm, report_df):
        """Save all evaluation results"""
        logger.info("Saving evaluation results...")
        
        # Save classification summary
        summary_content = f"""
=== MALWARE DETECTION CLASSIFICATION SUMMARY ===

Overall Metrics:
- Accuracy: {self.metrics['accuracy']:.4f}
- Macro Precision: {self.metrics['precision_macro']:.4f}
- Macro Recall: {self.metrics['recall_macro']:.4f}
- Macro F1-Score: {self.metrics['f1_macro']:.4f}
- Weighted Precision: {self.metrics['precision_weighted']:.4f}
- Weighted Recall: {self.metrics['recall_weighted']:.4f}
- Weighted F1-Score: {self.metrics['f1_weighted']:.4f}

Per-Class Metrics:
"""
        
        # Add per-class metrics
        for i, class_name in self.int_to_class.items():
            summary_content += f"""
{class_name}:
  - Precision: {self.metrics['per_class']['precision'][i]:.4f}
  - Recall: {self.metrics['per_class']['recall'][i]:.4f}
  - F1-Score: {self.metrics['per_class']['f1'][i]:.4f}
  - Support: {self.metrics['per_class']['support'][i]}
"""
        
        # Save to file
        with open(config.RESULTS_DIR / 'classification_summary.txt', 'w') as f:
            f.write(summary_content)
        
        # Save detailed report
        report_df.to_csv(config.RESULTS_DIR / 'detailed_classification_report.csv')
        
        # Save predictions
        predictions_df = pd.DataFrame({
            'filename': self.filenames,
            'true_class': [self.int_to_class[c] for c in self.true_classes],
            'predicted_class': [self.int_to_class[c] for c in self.predicted_classes],
            'confidence': np.max(self.predictions, axis=1)
        })
        predictions_df.to_csv(config.RESULTS_DIR / 'predictions.csv', index=False)
        
        logger.info("All evaluation results saved")

def main():
    """Main evaluation function"""
    try:
        logger.info("Starting model evaluation...")
        
        # Load processed data
        with open(config.MODELS_DIR / 'processed_data.pkl', 'rb') as f:
            processed_data = pickle.load(f)
        
        # Load class mapping
        with open(config.MODELS_DIR / 'class_mapping.pkl', 'rb') as f:
            class_mapping = pickle.load(f)
        
        X_test = processed_data['X_test']
        y_test = processed_data['y_test']
        y_int_test = processed_data['y_int_test']
        filenames_test = processed_data.get('filenames_test', [])
        
        # Load model
        model = tf.keras.models.load_model(config.MODELS_DIR / 'best_model.h5')
        logger.info("Loaded best model for evaluation")
        
        # Initialize evaluator
        evaluator = ModelEvaluator(
            model=model,
            X_test=X_test,
            y_test=y_test,
            y_int_test=y_int_test,
            int_to_class=class_mapping['int_to_class'],
            filenames=filenames_test
        )
        
        # Generate predictions
        evaluator.make_predictions()
        
        # Calculate metrics
        metrics = evaluator.calculate_metrics()
        
        # Generate plots
        cm = evaluator.plot_confusion_matrix()
        evaluator.plot_metrics_comparison()
        
        # Generate classification report
        report_df = evaluator.generate_classification_report()
        
        # Save results
        evaluator.save_results(cm, report_df)
        
        # Print summary
        logger.info("\n=== EVALUATION SUMMARY ===")
        logger.info(f"Accuracy: {metrics['accuracy']:.4f}")
        logger.info(f"Macro F1-Score: {metrics['f1_macro']:.4f}")
        logger.info(f"Weighted F1-Score: {metrics['f1_weighted']:.4f}")
        logger.info(f"Test samples: {len(X_test)}")
        
        logger.info("Model evaluation completed successfully!")
        
    except Exception as e:
        logger.error(f"Error in model evaluation: {e}")
        raise

if __name__ == "__main__":
    main()