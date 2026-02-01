import pandas as pd
import seaborn as sns
import matplotlib.pyplot as plt
import numpy as np
import os
import math

# Configuration
DATA_DIR = "./data"
OUTPUT_IMG_DIR = "./analysis_plots"
FILE_HTML_ONLY = os.path.join(DATA_DIR, "features_dataset.csv")
FILE_WITH_URL = os.path.join(DATA_DIR, "features_dataset_with_url.csv")

def get_best_dataset():
    """Prioritizes the dataset with URL features if it exists."""
    if os.path.exists(FILE_WITH_URL):
        print(f"Loading Extended Dataset: {FILE_WITH_URL}")
        return pd.read_csv(FILE_WITH_URL)
    elif os.path.exists(FILE_HTML_ONLY):
        print(f"Loading Basic Dataset: {FILE_HTML_ONLY}")
        return pd.read_csv(FILE_HTML_ONLY)
    else:
        return None

def save_plot(fig, filename):
    path = os.path.join(OUTPUT_IMG_DIR, filename)
    fig.savefig(path)
    print(f"Saved plot to {path}")
    plt.close(fig)

def analyze():
    # 1. Load Data
    df = get_best_dataset()
    if df is None:
        print("Error: No dataset found in ./data/")
        return

    os.makedirs(OUTPUT_IMG_DIR, exist_ok=True)
    print(f"Loaded {len(df)} samples.")
    print("-" * 30)

    # Clean up any potential NaN in numeric columns for analysis
    numeric_df = df.select_dtypes(include=[np.number]).fillna(0)

    # ==========================================
    # 1. CORRELATION ANALYSIS
    # ==========================================
    for target in ['target_malware', 'target_adware']:
        if target in numeric_df.columns:
            print(f"\n--- Top Correlations with {target.upper()} ---")
            corr = numeric_df.corr()[target].sort_values(ascending=False)
            # Filter out the target itself
            corr = corr.drop([target, 'target_malware', 'target_adware'], errors='ignore')
            print(corr.head(5))
            print("...")
            print(corr.tail(5))

    # Heatmap
    plt.figure(figsize=(14, 12))
    sns.heatmap(numeric_df.corr(), cmap='coolwarm', annot=False, center=0)
    plt.title("Feature Correlation Matrix")
    plt.tight_layout()
    save_plot(plt.gcf(), "correlation_heatmap.png")

    # ==========================================
    # 2. FEATURE GROUPS
    # ==========================================
    # We separate features into groups for better visualization
    
    # Continuous Features (Best for Box Plots)
    feat_continuous = [
        'num_script_tags', 'text_ratio', 'num_iframes', 'num_external_links',
        'html_len', 'path_len', 'domain_len', 'domain_digits', 
        'kw_malware', 'kw_adware'
    ]
    
    # Boolean/Binary Features (Best for Bar/Count Plots)
    feat_boolean = [
        'is_https', 'has_title', 'count_eval', 'count_unescape' 
        # Note: count_eval is technically continuous, but usually 0 or 1, so fits here often
    ]

    # Filter checks to ensure columns exist (in case we loaded the old CSV)
    feat_continuous = [f for f in feat_continuous if f in df.columns]
    feat_boolean = [f for f in feat_boolean if f in df.columns]

    # ==========================================
    # 3. DISTRIBUTION PLOTS (Continuous)
    # ==========================================
    print("\n--- Generating Continuous Distribution Plots ---")
    
    # Calculate grid size
    n_cols = 3
    n_rows = math.ceil(len(feat_continuous) / n_cols)
    
    fig, axes = plt.subplots(n_rows, n_cols, figsize=(15, 4 * n_rows))
    axes = axes.flatten()

    for i, feature in enumerate(feat_continuous):
        # Log scale helper for highly skewed data
        # We create a temporary column for plotting
        plot_data = df.copy()
        if plot_data[feature].max() > 100: # Apply log if values are large
            plot_data[feature] = np.log1p(plot_data[feature])
            y_label = f"Log({feature})"
        else:
            y_label = feature

        sns.boxplot(x='label_class', y=feature, data=plot_data, ax=axes[i], showfliers=False)
        axes[i].set_title(f"{feature} Distribution")
        axes[i].set_ylabel(y_label)
        axes[i].set_xlabel("")

    # Hide empty subplots
    for i in range(len(feat_continuous), len(axes)):
        fig.delaxes(axes[i])

    plt.tight_layout()
    save_plot(fig, "feature_distributions_continuous.png")

    # ==========================================
    # 4. CATEGORICAL/BOOLEAN PLOTS
    # ==========================================
    print("--- Generating Boolean/Category Plots ---")
    
    if feat_boolean:
        n_rows_bool = math.ceil(len(feat_boolean) / n_cols)
        fig2, axes2 = plt.subplots(n_rows_bool, n_cols, figsize=(15, 4 * n_rows_bool))
        axes2 = axes2.flatten() if len(feat_boolean) > 1 else [axes2]

        for i, feature in enumerate(feat_boolean):
            # Check if feature is effectively binary
            if df[feature].nunique() <= 5:
                # Bar plot showing the MEAN (percentage of True)
                # e.g. % of sites that have HTTPS
                sns.barplot(x='label_class', y=feature, data=df, ax=axes2[i], errorbar=None)
                axes2[i].set_title(f"Avg {feature} (Proportion)")
                axes2[i].set_ylabel("Rate (0 to 1)")
            else:
                # If it's a count (like 0, 1, 2, 3), use boxplot
                sns.boxplot(x='label_class', y=feature, data=df, ax=axes2[i], showfliers=False)
                axes2[i].set_title(f"{feature} Distribution")

        # Hide empty subplots
        for i in range(len(feat_boolean), len(axes2)):
            fig2.delaxes(axes2[i])

        plt.tight_layout()
        save_plot(fig2, "feature_distributions_boolean.png")

    # ==========================================
    # 5. HTTPS & PATH STATS (Text Report)
    # ==========================================
    if 'is_https' in df.columns:
        print("\n--- HTTPS Adoption Rate ---")
        print(df.groupby('label_class')['is_https'].mean())
    
    if 'path_len' in df.columns:
        print("\n--- Average URL Path Length ---")
        print(df.groupby('label_class')['path_len'].mean())

    if 'domain_digits' in df.columns:
        print("\n--- Average Digits in Domain ---")
        print(df.groupby('label_class')['domain_digits'].mean())

    # ==========================================
    # 6. CLASS BALANCE CHECK
    # ==========================================
    plt.figure(figsize=(6, 4))
    sns.countplot(x='label_class', data=df)
    plt.title("Class Balance")
    save_plot(plt.gcf(), "class_balance.png")

if __name__ == "__main__":
    analyze()