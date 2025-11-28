#!/usr/bin/env python3
"""
t-SNE Visualization Script for Deep Malware APT group Identification
Creates 2D visualization of the learned feature representations
"""
import sys
import os
# Add the scripts directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

import logging
import pickle
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.manifold import TSNE
from sklearn.decomposition import PCA
import tensorflow as tf
import config

# Setup logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(config.LOGS_DIR / 'tsne_visualization.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger('tsne')

class TSNEVisualizer:
    def __init__(self, model, X_data, y_int, int_to_class):
        self.model = model
        self.X_data = X_data
        self.y_int = y_int
        self.int_to_class = int_to_class
        self.feature_model = None
        
    def create_feature_extractor(self):
        """Create a model that extracts features from the layer before classification"""
        logger.info("Creating feature extraction model...")
        
        try:
            # Try to get the hidden layer (adjust name if different in your model)
            hidden_layer_output = None
            for layer in self.model.layers:
                if 'hidden' in layer.name or 'dense' in layer.name:
                    if layer != self.model.layers[-1]:  # Not the output layer
                        hidden_layer_output = layer.output
                        logger.info(f"Using layer '{layer.name}' for feature extraction")
                        break
            
            # Fallback: use the second-to-last layer
            if hidden_layer_output is None:
                hidden_layer_output = self.model.layers[-2].output
                logger.info(f"Fallback: Using layer '{self.model.layers[-2].name}' for feature extraction")
            
            self.feature_model = tf.keras.Model(
                inputs=self.model.input,
                outputs=hidden_layer_output
            )
            
            logger.info("Feature extraction model created successfully")
            
        except Exception as e:
            logger.error(f"Error creating feature extractor: {e}")
            raise
        
    def extract_features(self):
        """Extract features from the hidden layer"""
        logger.info("Extracting features from hidden layer...")
        
        if self.feature_model is None:
            self.create_feature_extractor()
        
        features = self.feature_model.predict(self.X_data, verbose=0)
        logger.info(f"Extracted features shape: {features.shape}")
        
        return features
    
    def perform_tsne(self, features, n_components=2, perplexity=30):
        """Perform t-SNE dimensionality reduction with robust error handling"""
        logger.info("Performing t-SNE dimensionality reduction...")
        
        n_samples, n_features = features.shape
        logger.info(f"Input features: {n_samples} samples, {n_features} dimensions")
        
        # Adjust perplexity based on sample size
        actual_perplexity = min(perplexity, n_samples - 1)
        if actual_perplexity < 5:
            actual_perplexity = max(5, n_samples // 10)  # Minimum sensible perplexity
            
        if actual_perplexity != perplexity:
            logger.info(f"Adjusted perplexity from {perplexity} to {actual_perplexity}")
        
        # Handle high-dimensional data with PCA if needed
        if n_features > 50:
            # Use PCA for dimensionality reduction first
            max_pca_components = min(50, n_samples - 1, n_features)
            logger.info(f"Applying PCA with {max_pca_components} components")
            
            pca = PCA(n_components=max_pca_components, random_state=42)
            features_reduced = pca.fit_transform(features)
            explained_variance = pca.explained_variance_ratio_.sum()
            logger.info(f"PCA explained variance: {explained_variance:.3f}")
        else:
            # Use features directly if already low-dimensional
            features_reduced = features
            logger.info("Using original features (low-dimensional)")
        
        # Perform t-SNE with compatibility for different scikit-learn versions
        try:
            # Try with max_iter (newer scikit-learn versions)
            tsne = TSNE(
                n_components=n_components,
                perplexity=actual_perplexity,
                random_state=42,
                max_iter=1000,
                learning_rate=200,
                init='random',
                verbose=1
            )
            
            features_tsne = tsne.fit_transform(features_reduced)
            logger.info(f"t-SNE transformation completed: {features_tsne.shape}")
            
        except TypeError as e:
            if 'max_iter' in str(e):
                # Fallback to n_iter (older scikit-learn versions)
                logger.info("Using 'n_iter' parameter (older scikit-learn version)")
                tsne = TSNE(
                    n_components=n_components,
                    perplexity=actual_perplexity,
                    random_state=42,
                    n_iter=1000,
                    learning_rate=200,
                    init='random',
                    verbose=1
                )
                features_tsne = tsne.fit_transform(features_reduced)
                logger.info(f"t-SNE transformation completed: {features_tsne.shape}")
            else:
                raise e
        except Exception as e:
            logger.warning(f"Standard t-SNE failed: {e}. Trying simplified version...")
            # Fallback to simplest t-SNE
            try:
                tsne = TSNE(
                    n_components=n_components,
                    perplexity=min(actual_perplexity, 30),
                    random_state=42,
                    max_iter=500
                )
                features_tsne = tsne.fit_transform(features_reduced)
                logger.info(f"Simplified t-SNE completed: {features_tsne.shape}")
            except TypeError:
                # Try with n_iter for older versions
                tsne = TSNE(
                    n_components=n_components,
                    perplexity=min(actual_perplexity, 30),
                    random_state=42,
                    n_iter=500
                )
                features_tsne = tsne.fit_transform(features_reduced)
                logger.info(f"Simplified t-SNE (n_iter) completed: {features_tsne.shape}")
        
        return features_tsne
    
    def plot_tsne(self, features_tsne, title_suffix=""):
        """Plot t-SNE visualization"""
        logger.info("Creating t-SNE visualization plot...")
        
        try:
            # Set style
            plt.style.use('default')
            plt.rcParams['font.family'] = 'DejaVu Sans'
            
            # Create figure
            fig, ax = plt.subplots(figsize=(14, 10))
            
            # Get class labels
            unique_classes = sorted(set(self.y_int))
            n_classes = len(unique_classes)
            
            # Use a colormap that can handle many classes
            if n_classes <= 10:
                colors = plt.cm.Set3(np.linspace(0, 1, n_classes))
            elif n_classes <= 20:
                colors = plt.cm.tab20(np.linspace(0, 1, n_classes))
            else:
                colors = plt.cm.gist_ncar(np.linspace(0, 1, n_classes))
            
            # Create scatter plot for each class
            for i, class_id in enumerate(unique_classes):
                mask = np.array(self.y_int) == class_id
                if np.sum(mask) > 0:  # Only plot if there are samples
                    class_name = self.int_to_class[class_id]
                    ax.scatter(
                        features_tsne[mask, 0],
                        features_tsne[mask, 1],
                        c=[colors[i]],
                        label=class_name,
                        alpha=0.7,
                        s=50,
                        edgecolors='w',
                        linewidth=0.5
                    )
            
            # Customize plot
            ax.set_title(f't-SNE Visualization of APT Group Feature Representations {title_suffix}', 
                        fontsize=16, fontweight='bold', pad=20)
            ax.set_xlabel('t-SNE Component 1', fontsize=12, fontweight='bold')
            ax.set_ylabel('t-SNE Component 2', fontsize=12, fontweight='bold')
            ax.grid(True, alpha=0.3)
            
            # Create legend
            ax.legend(bbox_to_anchor=(1.05, 1), loc='upper left', 
                     fontsize=9, framealpha=0.9)
            
            plt.tight_layout()
            
            # Save plot
            filename = config.IMG_DIR / f'tsne_visualization_perplexity_{title_suffix.replace("(", "").replace(")", "").replace("=", "_").replace(" ", "_").lower()}.png'
            plt.savefig(filename, dpi=300, bbox_inches='tight')
            plt.close()
            
            logger.info(f"t-SNE visualization plot saved: {filename}")
            
        except Exception as e:
            logger.error(f"Error creating t-SNE plot: {e}")
            raise
    
    def analyze_feature_separation(self, features_tsne):
        """Analyze how well features are separated in t-SNE space"""
        logger.info("Analyzing feature separation...")
        
        try:
            # Calculate inter-class distances
            unique_classes = sorted(set(self.y_int))
            class_centers = {}
            class_spreads = {}
            
            for class_id in unique_classes:
                mask = np.array(self.y_int) == class_id
                if np.sum(mask) > 1:  # Need at least 2 points for spread calculation
                    class_points = features_tsne[mask]
                    class_centers[class_id] = np.mean(class_points, axis=0)
                    class_spreads[class_id] = np.mean(np.std(class_points, axis=0))
            
            # Calculate average distance between class centers
            if len(class_centers) > 1:
                centers = list(class_centers.values())
                distances = []
                for i in range(len(centers)):
                    for j in range(i + 1, len(centers)):
                        dist = np.linalg.norm(centers[i] - centers[j])
                        distances.append(dist)
                
                avg_distance = np.mean(distances)
                avg_spread = np.mean(list(class_spreads.values()))
                
                separation_ratio = avg_distance / avg_spread if avg_spread > 0 else 0
                
                logger.info(f"Feature separation analysis:")
                logger.info(f"  - Average inter-class distance: {avg_distance:.3f}")
                logger.info(f"  - Average intra-class spread: {avg_spread:.3f}")
                logger.info(f"  - Separation ratio: {separation_ratio:.3f}")
                
                return separation_ratio
            else:
                logger.warning("Not enough classes for separation analysis")
                return 0
                
        except Exception as e:
            logger.warning(f"Could not complete separation analysis: {e}")
            return 0
    
    def create_comprehensive_visualization(self):
        """Create comprehensive t-SNE visualization with multiple perplexities"""
        logger.info("Starting comprehensive t-SNE visualization...")
        
        # Extract features
        features = self.extract_features()
        n_samples = features.shape[0]
        
        logger.info(f"Working with {n_samples} samples and {features.shape[1]} features")
        
        # Define perplexities based on sample size
        if n_samples < 100:
            perplexities = [5, min(10, n_samples - 1)]
        elif n_samples < 300:
            perplexities = [15, 30]
        else:
            perplexities = [30, 50]
        
        # Remove invalid perplexities
        perplexities = [p for p in perplexities if p < n_samples and p >= 5]
        
        if not perplexities:
            perplexities = [min(30, max(5, n_samples // 10))]
        
        logger.info(f"Using perplexities: {perplexities}")
        
        separation_results = {}
        
        for perplexity in perplexities:
            try:
                logger.info(f"Generating t-SNE with perplexity {perplexity}...")
                features_tsne = self.perform_tsne(features, perplexity=perplexity)
                
                # Create visualization
                self.plot_tsne(features_tsne, f"(Perplexity={perplexity})")
                
                # Analyze separation
                separation_ratio = self.analyze_feature_separation(features_tsne)
                separation_results[perplexity] = separation_ratio
                
                logger.info(f"t-SNE with perplexity {perplexity} completed successfully")
                
            except Exception as e:
                logger.error(f"t-SNE with perplexity {perplexity} failed: {e}")
                continue
        
        # Log summary
        if separation_results:
            best_perplexity = max(separation_results, key=separation_results.get)
            logger.info(f"Best separation achieved with perplexity {best_perplexity}: {separation_results[best_perplexity]:.3f}")
        
        return separation_results

def main():
    """Main t-SNE visualization function"""
    try:
        logger.info("Starting t-SNE visualization process...")
        
        # Load processed data
        data_path = config.MODELS_DIR / 'processed_data.pkl'
        if not data_path.exists():
            logger.error(f"Processed data file not found: {data_path}")
            return
        
        with open(data_path, 'rb') as f:
            processed_data = pickle.load(f)
        
        # Load class mapping
        mapping_path = config.MODELS_DIR / 'class_mapping.pkl'
        if not mapping_path.exists():
            logger.error(f"Class mapping file not found: {mapping_path}")
            return
            
        with open(mapping_path, 'rb') as f:
            class_mapping = pickle.load(f)
        
        # Use test data for visualization
        X_test = processed_data['X_test']
        y_int_test = processed_data['y_int_test']
        
        logger.info(f"Loaded test data: {X_test.shape} samples")
        
        # Subsample if too many points for clear visualization
        max_points = 1000
        if len(X_test) > max_points:
            indices = np.random.choice(len(X_test), max_points, replace=False)
            X_vis = X_test[indices]
            y_int_vis = [y_int_test[i] for i in indices]
            logger.info(f"Subsampled to {max_points} points for clearer visualization")
        else:
            X_vis = X_test
            y_int_vis = y_int_test
        
        # Load model
        model_path = config.MODELS_DIR / 'best_model.h5'
        if not model_path.exists():
            logger.error(f"Model file not found: {model_path}")
            return
            
        logger.info("Loading trained model...")
        model = tf.keras.models.load_model(model_path)
        
        # Create visualizer
        visualizer = TSNEVisualizer(
            model=model,
            X_data=X_vis,
            y_int=y_int_vis,
            int_to_class=class_mapping['int_to_class']
        )
        
        # Generate visualization
        separation_results = visualizer.create_comprehensive_visualization()
        
        if separation_results:
            logger.info("t-SNE visualization completed successfully!")
            logger.info(f"Generated {len(separation_results)} t-SNE visualizations")
        else:
            logger.warning("t-SNE visualization completed with errors - no successful visualizations generated")
        
    except Exception as e:
        logger.error(f"Error in t-SNE visualization process: {e}")
        raise

if __name__ == "__main__":
    main()