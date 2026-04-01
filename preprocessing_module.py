import pandas as pd
from sklearn.preprocessing import StandardScaler, MultiLabelBinarizer
import keras
from tensorflow.keras.utils import to_categorical
from sklearn.ensemble import RandomForestClassifier

def load_data(file_path):
    # Load the data
    column_names = ['Duration', 'Protocol_type', 'Service', 'Flag', 'Src_bytes', 'Dst_bytes', 'Land', 'Wrong_fragment','Urgent', 'Hot', 'Num_failed_logins', 'Logged_in', 'Num_compromised', 'Root_shell', 'Su_attempted','Num_root', 'Num_file_creations', 'Num_shells', 'Num_access_files', 'Num_outbound_cmds', 'Is_host_login','Is_guest_login', 'Count', 'Srv_count', 'Serror_rate', 'Srv_serror_rate', 'Rerror_rate', 'Srv_rerror_rate','Same_srv_rate', 'Diff_srv_rate', 'Srv_diff_host_rate', 'Dst_host_count', 'Dst_host_srv_count',
        'Dst_host_same_srv_rate', 'Dst_host_diff_srv_rate', 'Dst_host_same_src_port_rate', 'Dst_host_srv_diff_host_rate',
        'Dst_host_serror_rate', 'Dst_host_srv_serror_rate', 'Dst_host_rerror_rate', 'Dst_host_srv_rerror_rate',
        'Attack_Type', 'Difficulty_Level'
    ]  # Define column names
    raw_data = pd.read_csv(file_path, names=column_names)
    df = raw_data.copy()
    return df

def preprocess_data(data):
    
    # Selecting only categorical columns for encoding
    categorical_cols = ['Protocol_type', 'Service', 'Flag']

    # Applying one-hot encoding using Pandas get_dummies
    encoded_df = pd.get_dummies(data[categorical_cols], drop_first=True)

    # Dropping the original categorical columns from the original DataFrame
    data = data.drop(columns=categorical_cols)

    # Concatenating the original DataFrame with the encoded categorical DataFrame
    data_encoded = pd.concat([data, encoded_df], axis=1)
    
    return data_encoded

def feature_selection (data_encoded,y):
    # Feature selection or any other preprocessing steps if needed
    clf = RandomForestClassifier(n_estimators=100, random_state=42)
    clf.fit(data_encoded, y)
    feature_importances = clf.feature_importances_
    feature_importance_df = pd.DataFrame({'Feature': data_encoded.columns, 'Importance': feature_importances})

    # Sort the features by importance in descending order
    feature_importance_df = feature_importance_df.sort_values(by='Importance', ascending=False)

    # Display the top N features
    top_n = 10  # Define the number of top features you want to display

    # Show the top N features and their importance scores
    top_features = feature_importance_df.head(29)

    top_feature_names = top_features['Feature'].tolist()

    # Extract the top features from the original DataFrame 'X'
    X_top_features = data_encoded[top_feature_names]
    return X_top_features


def preprocess_target_variable(y):
    # Convert the strings in 'y' to lists of attack types
    y_list = [labels.split(',') for labels in y]  # Assuming labels are comma-separated

    # Initialize and fit the MultiLabelBinarizer
    mlb = MultiLabelBinarizer()
    y_dum = mlb.fit_transform(y_list)

    return y_dum

def scale_features(X):
    # Perform feature scaling using StandardScaler
    scaler = StandardScaler()
    x_scaled = scaler.fit_transform(X)
    return x_scaled

def preprocess_all(file_path):
    # Load the data
    data = load_data(file_path)

    # Preprocess target variable
    y = preprocess_target_variable(data['Attack_Type'])  # Target variable

    # Preprocess features
    X = preprocess_data(data.drop('Attack_Type', axis=1))  # Features
    X_imp = feature_selection(X,y)
    X_scaled = scale_features(X_imp)

    return X_scaled, y