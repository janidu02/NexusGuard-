import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import mean_squared_error
import joblib
import os
import numpy as np

# Constants
MODEL_FILE = 'trained_model.pkl'
TRAINED_MEMORY = 'trained_data.csv'

# Function to load or initialize the training dataset
def load_training_data(file_path):
    if os.path.exists(TRAINED_MEMORY):
        print("Loading previously trained data...")
        prev_data = pd.read_csv(TRAINED_MEMORY)
        new_data = pd.read_csv(file_path)
        return pd.concat([prev_data, new_data], ignore_index=True)
    else:
        print("No previous training data found. Using current dataset...")
        return pd.read_csv(file_path)

# Function to train the model
def train_model(df):
    print("Training the model...")
    X = df.drop(columns=['event_id', 'timestamp_utc', 'command_line', 'user_name', 'exit_code', 'malicious_score'])
    y = df['malicious_score']
    
    # Train-test split for validation
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    # Create Random Forest model
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train, y_train)
    
    # Evaluate the model
    predictions = model.predict(X_test)
    mse = mean_squared_error(y_test, predictions)
    print(f'Model Training Complete. Mean Squared Error: {mse}')
    
    # Save the model
    joblib.dump(model, MODEL_FILE)
    # Save the updated training data
    df.to_csv(TRAINED_MEMORY, index=False)
    print(f"Model saved as {MODEL_FILE} and training data updated.")

# Function to predict malicious scores and categorization
def predict_scores(file_path):
    print("Loading model and making predictions...")
    model = joblib.load(MODEL_FILE)
    
    # Load the new data without malicious scores for prediction
    df_new = pd.read_csv(file_path)
    
    # Prepare the data for prediction
    X_new = df_new.drop(columns=['event_id', 'timestamp_utc', 'command_line', 'user_name', 'exit_code'])
    
    # Predict the malicious scores
    scores = model.predict(X_new)
    
    # Add the scores to the DataFrame
    df_new['malicious_score'] = scores
    
    # Categorize based on the scores
    df_new['malicious_level'] = pd.cut(df_new['malicious_score'], bins=[-1, 29, 69, 100], labels=['normal', 'suspicious', 'malicious'])
    
    # Save the prediction results to a new CSV file
    output_file = file_path.replace('.csv', '_predictions.csv')
    df_new.to_csv(output_file, index=False)
    
    print(f"Predictions complete. Output saved as {output_file}")

def main():
    while True:
        print("\nSelect an option:")
        print("1. Input CSV for training")
        print("2. Train model")
        print("3. Predict on new dataset")
        print("4. Exit")
        
        choice = input("Enter your choice: ")
        
        if choice == '1':
            file_path = input("Enter the file path of the CSV for training data: ")
            training_data = load_training_data(file_path)
        
        elif choice == '2':
            if 'training_data' not in locals():
                print("No training data available. Please input a CSV first.")
            else:
                train_model(training_data)
        
        elif choice == '3':
            file_path = input("Enter the file path of the CSV for prediction: ")
            predict_scores(file_path)
        
        elif choice == '4':
            print("Exiting the program.")
            break
        
        else:
            print("Invalid choice. Please select a valid option.")

if __name__ == "__main__":
    main()
