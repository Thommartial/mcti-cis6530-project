#!/usr/bin/env python3
"""
Professional Model Visualization for MITRE ATT&CK Group Identification CNN
Two-row layout to ensure all layers are clearly visible
"""

import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import FancyBboxPatch, Rectangle
import matplotlib.patches as patches
import sys
import os

# Add config to path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))
import config

def create_professional_model_visualization():
    """Create a clean, professional model architecture diagram with two-row layout"""
    
    # Create figure with good proportions for two rows
    fig, ax = plt.subplots(1, 1, figsize=(16, 12))
    fig.patch.set_facecolor('white')
    ax.set_facecolor('white')
    
    # Set up the plotting area
    ax.set_xlim(0, 14)
    ax.set_ylim(0, 12)
    ax.axis('off')
    
    # Define layer properties with professional color scheme
    # First row: Input to GlobalMaxPool
    first_row_layers = [
        {"name": "Input", "type": "Input", "units": "API Call\nSequence\n(Length=1000)", "color": "#4A90E2", "x": 1, "y": 9},
        {"name": "Embedding", "type": "Embedding", "units": "Vocab Size\nEmbed Dim=128", "color": "#50E3C2", "x": 3.5, "y": 9},
        {"name": "Conv1D", "type": "Convolution", "units": "128 Filters\nKernel=5", "color": "#9013FE", "x": 6, "y": 9},
        {"name": "BatchNorm", "type": "Normalization", "units": "Batch\nNormalization", "color": "#F5A623", "x": 8.5, "y": 9},
        {"name": "GlobalMaxPool", "type": "Pooling", "units": "Global\nMax Pooling", "color": "#D0021B", "x": 11, "y": 9},
    ]
    
    # Second row: Dense to Output (centered below)
    second_row_layers = [
        {"name": "Dense", "type": "Fully Connected", "units": "128 Units\nReLU", "color": "#7ED321", "x": 5, "y": 5},
        {"name": "Dropout", "type": "Regularization", "units": "Dropout\nRate=0.5", "color": "#8B572A", "x": 8, "y": 5},
        {"name": "Output", "type": "Output", "units": "MITRE Groups\nSoftmax", "color": "#BD10E0", "x": 11, "y": 5},
    ]
    
    all_layers = first_row_layers + second_row_layers
    
    # Draw layers
    for layer in all_layers:
        # Main layer box
        box = FancyBboxPatch((layer["x"], layer["y"]), 1.8, 1.8, 
                           boxstyle="round,pad=0.05", 
                           facecolor=layer["color"], 
                           edgecolor='black', 
                           linewidth=1.5,
                           alpha=0.9)
        ax.add_patch(box)
        
        # Layer name
        ax.text(layer["x"] + 0.9, layer["y"] + 1.4, layer["name"], 
                ha='center', va='center', fontsize=12, fontweight='bold',
                color='white', fontfamily='sans-serif')
        
        # Layer type
        ax.text(layer["x"] + 0.9, layer["y"] + 1.1, layer["type"], 
                ha='center', va='center', fontsize=10,
                color='white', fontfamily='sans-serif', style='italic')
        
        # Layer units
        ax.text(layer["x"] + 0.9, layer["y"] + 0.6, layer["units"], 
                ha='center', va='center', fontsize=9,
                color='white', fontfamily='monospace', weight='bold')
    
    # Draw connections between first row layers
    for i in range(len(first_row_layers) - 1):
        x1 = first_row_layers[i]["x"] + 1.8
        x2 = first_row_layers[i + 1]["x"]
        y = first_row_layers[i]["y"] + 0.9
        
        # Main connection line
        ax.plot([x1, x2], [y, y], 'k-', linewidth=2, alpha=0.8)
        
        # Arrow head
        ax.annotate('', xy=(x2, y), xytext=(x2-0.15, y),
                   arrowprops=dict(arrowstyle='->', color='black', lw=2))
    
    # Draw connections between second row layers
    for i in range(len(second_row_layers) - 1):
        x1 = second_row_layers[i]["x"] + 1.8
        x2 = second_row_layers[i + 1]["x"]
        y = second_row_layers[i]["y"] + 0.9
        
        # Main connection line
        ax.plot([x1, x2], [y, y], 'k-', linewidth=2, alpha=0.8)
        
        # Arrow head
        ax.annotate('', xy=(x2, y), xytext=(x2-0.15, y),
                   arrowprops=dict(arrowstyle='->', color='black', lw=2))
    
    # Draw connection from first row to second row (GlobalMaxPool to Dense)
    start_x = first_row_layers[-1]["x"] + 0.9  # Center of GlobalMaxPool
    start_y = first_row_layers[-1]["y"]  # Bottom of GlobalMaxPool
    end_x = second_row_layers[0]["x"] + 0.9    # Center of Dense
    end_y = second_row_layers[0]["y"] + 1.8    # Top of Dense
    
    # Vertical down line
    ax.plot([start_x, start_x], [start_y, start_y - 1], 'k-', linewidth=2, alpha=0.8)
    # Horizontal connection
    ax.plot([start_x, end_x], [start_y - 1, start_y - 1], 'k-', linewidth=2, alpha=0.8)
    # Vertical up line
    ax.plot([end_x, end_x], [start_y - 1, end_y], 'k-', linewidth=2, alpha=0.8)
    # Arrow head
    ax.annotate('', xy=(end_x, end_y), xytext=(end_x, end_y-0.15),
               arrowprops=dict(arrowstyle='->', color='black', lw=2))
    
    # Add feature maps visualization for Conv layer
    conv_x = first_row_layers[2]["x"] + 0.9
    for i in range(5):
        for j in range(3):
            rect = Rectangle((conv_x - 0.3 + i*0.12, first_row_layers[2]["y"] - 1.2 - j*0.12), 
                           0.1, 0.1, 
                           facecolor='#FF6B6B', alpha=0.7)
            ax.add_patch(rect)
    
    ax.text(conv_x, first_row_layers[2]["y"] - 2.0, "Feature Maps", 
            ha='center', va='center', fontsize=9, fontweight='bold',
            color='#333333', fontfamily='sans-serif')
    
    # Add pooling visualization
    pool_x = first_row_layers[4]["x"] + 0.9
    for i in range(3):
        rect = Rectangle((pool_x - 0.2 + i*0.15, first_row_layers[4]["y"] - 1.2), 
                       0.12, 0.12, 
                       facecolor='#4ECDC4', alpha=0.8)
        ax.add_patch(rect)
    
    ax.text(pool_x, first_row_layers[4]["y"] - 2.0, "Pooled Features", 
            ha='center', va='center', fontsize=9, fontweight='bold',
            color='#333333', fontfamily='sans-serif')
    
    # Add architecture description
    desc_bg = FancyBboxPatch((1, 0.5), 12, 2.0, 
                           boxstyle="round,pad=0.05", 
                           facecolor='#F8F9FA', 
                           edgecolor='#D1D5DB', 
                           linewidth=1.5,
                           alpha=0.9)
    ax.add_patch(desc_bg)
    
    architecture_details = [
        "• Input Layer: Raw API call sequences from malware samples (fixed length: 1000)",
        "• Embedding Layer: Learn semantic relationships between API calls (embedding dimension: 128)", 
        "• Conv1D Layer: Extract local temporal patterns using 128 filters (kernel size: 5)",
        "• Batch Normalization: Stabilize and accelerate training",
        "• Global Max Pooling: Capture most salient features across entire sequence",
        "• Dense Layer: Fully connected layer with 128 units and ReLU activation",
        "• Dropout: Regularization to prevent overfitting (rate: 0.5)",
        "• Output Layer: Classification into MITRE ATT&CK APT Groups using Softmax"
    ]
    
    for i, detail in enumerate(architecture_details):
        row = i // 2
        col = i % 2
        ax.text(1.5 + col * 6, 2.0 - row * 0.25, detail, 
                ha='left', va='center', fontsize=9,
                color='#333333', fontfamily='sans-serif')
    
    # Add model purpose
    purpose_text = "CNN Architecture for MITRE ATT&CK APT Group Identification"
    ax.text(7, 11.5, purpose_text, 
            ha='center', va='center', fontsize=16, fontweight='bold',
            color='#2C3E50', fontfamily='sans-serif')
    
    # Add data flow direction indicators
    ax.text(7, 10.5, "Data Flow →", 
            ha='center', va='center', fontsize=11, fontweight='bold',
            color='#666666', fontfamily='sans-serif', style='italic')
    
    ax.text(8, 7.0, "Data Flow →", 
            ha='center', va='center', fontsize=11, fontweight='bold',
            color='#666666', fontfamily='sans-serif', style='italic')
    
    plt.tight_layout(pad=3.0)
    
    # Save the visualization
    try:
        plt.savefig(config.IMG_DIR / 'mitre_apt_group_cnn_architecture.png', 
                   dpi=300, bbox_inches='tight', facecolor='white',
                   transparent=False, pad_inches=1.0)
        print(f"Model visualization saved to {config.IMG_DIR / 'mitre_apt_group_cnn_architecture.png'}")
    except Exception as e:
        print(f"Could not save visualization: {e}")
        # Save to current directory as fallback
        plt.savefig('mitre_apt_group_cnn_architecture.png', 
                   dpi=300, bbox_inches='tight', facecolor='white',
                   pad_inches=1.0)
    
    plt.close()

if __name__ == "__main__":
    print("Creating professional model visualization for MITRE ATT&CK Group Identification...")
    create_professional_model_visualization()
    print("Visualization generation completed!")