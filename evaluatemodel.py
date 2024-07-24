import os
import pandas as pd
import pickle
import argparse
import numpy as np
import warnings
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
import tensorflow as tf
from colorama import Fore, Style, init
import logging

# Initialize colorama
init(autoreset=True)

# Set environment variables to suppress TensorFlow warnings
os.environ['TF_CPP_MIN_LOG_LEVEL'] = '3'  # Suppresses all logs except errors
tf.get_logger().setLevel('ERROR')  # Only show errors
logging.getLogger('tensorflow').setLevel(logging.ERROR)

warnings.filterwarnings('ignore')  # To ignore warnings that are not critical

def clean_data(data):
    # Identify numeric columns and apply conversion only to those
    numeric_columns = ['response_code', 'response_time']  # Add other numeric columns if needed
    for col in numeric_columns:
        data[col] = pd.to_numeric(data[col], errors='coerce')

    # Drop rows with any NaN values in numeric columns
    data = data.dropna(subset=numeric_columns)

    return data

def evaluate_performance(accuracy):
    if accuracy >= 0.9:
        return f"{Fore.GREEN}Good performance. The model is highly accurate."
    elif 0.75 <= accuracy < 0.9:
        return f"{Fore.YELLOW}Fair performance. The model is reasonably accurate but may need improvement."
    else:
        return f"{Fore.RED}Poor performance. The model accuracy is low and requires significant improvement."

def main(csv_file_path, pkl_file_path):
    try:
        # Load the CSV training data with error handling
        data = pd.read_csv(csv_file_path, on_bad_lines='skip')

        # Print the shape of the data
        print(f"Data shape before cleaning: {data.shape}")

        # Assume the last column is the target variable (y) and the rest are features (X)
        X = data.iloc[:, :-1]  # Features
        y = data.iloc[:, -1]   # Target

        # Clean the features
        X = clean_data(X)

        # Print the shape of the cleaned data
        print(f"Data shape after cleaning: {X.shape}")

        # Ensure target variable (y) aligns with cleaned features (X)
        y = y[X.index]

        # Convert all feature data to numeric type and handle remaining NaNs
        X = X.apply(pd.to_numeric, errors='coerce').fillna(0)

        # Print the first few rows of the cleaned data
        print(f"First few rows of the cleaned features:\n{X.head()}")
        print(f"First few rows of the target variable:\n{y.head()}")

        # Load the trained model from the .pkl file
        with open(pkl_file_path, 'rb') as file:
            model = pickle.load(file)

        # Ensure target variable (y) is numeric
        y = pd.to_numeric(y, errors='coerce').fillna(0)

        # Select the first two columns for compatibility with the model
        X_selected = X.iloc[:, :2]  # Adjust this as needed to match the model's input requirements

        # Print the shape of the selected data
        print(f"Shape of the selected features: {X_selected.shape}")

        # Use the model to make predictions
        predictions = model.predict(X_selected)

        # Print the predictions
        print("Predictions:")
        print(predictions)

        # Evaluate the model (if it's a classification model)
        accuracy = accuracy_score(y, predictions)
        print(f"Accuracy: {accuracy}")

        # Generate the confusion matrix
        conf_matrix = confusion_matrix(y, predictions)
        print("Confusion Matrix:")
        print(conf_matrix)

        # Generate a classification report
        class_report = classification_report(y, predictions)
        print("Classification Report:")
        print(class_report)

        # Provide an explanation of the performance
        performance_explanation = evaluate_performance(accuracy)
        print(performance_explanation)

    except Exception as e:
        print(f"An error occurred: {e}")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Load a model and make predictions using CSV training data.')
    parser.add_argument('csv_file_path', type=str, help='Path to the CSV file containing the training data')
    parser.add_argument('pkl_file_path', type=str, help='Path to the .pkl file containing the trained model')

    args = parser.parse_args()
    main(args.csv_file_path, args.pkl_file_path)
