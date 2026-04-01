from preprocessing_module import preprocess_all
import numpy as np
from tensorflow.keras.models import load_model


loaded_model = load_model('trained_model.h5')

attacks = [
    'normal', 'neptune', 'warezclient', 'ipsweep', 'portsweep',
    'teardrop', 'nmap', 'satan', 'smurf', 'pod', 'back',
    'guess_passwd', 'ftp_write', 'multihop', 'rootkit',
    'buffer_overflow', 'imap', 'warezmaster', 'phf', 'land',
    'loadmodule', 'spy', 'perl'
]

attacks_dict = {
    0: {'type': 'normal', 'threat_level': 'low'},
    1: {'type': 'neptune', 'threat_level': 'critical'},
    2: {'type': 'warezclient', 'threat_level': 'high'},
    3: {'type': 'ipsweep', 'threat_level': 'medium-high'},
    4: {'type': 'portsweep', 'threat_level': 'medium-high'},
    5: {'type': 'teardrop', 'threat_level': 'critical'},
    6: {'type': 'nmap', 'threat_level': 'medium-high'},
    7: {'type': 'satan', 'threat_level': 'medium-high'},
    8: {'type': 'smurf', 'threat_level': 'critical'},
    9: {'type': 'pod', 'threat_level': 'critical'},
    10: {'type': 'back', 'threat_level': 'critical'},
    11: {'type': 'guess_passwd', 'threat_level': 'critical'},
    12: {'type': 'ftp_write', 'threat_level': 'high'},
    13: {'type': 'multihop', 'threat_level': 'high'},
    14: {'type': 'rootkit', 'threat_level': 'critical'},
    15: {'type': 'buffer_overflow', 'threat_level': 'critical'},
    16: {'type': 'imap', 'threat_level': 'high'},
    17: {'type': 'warezmaster', 'threat_level': 'high'},
    18: {'type': 'phf', 'threat_level': 'critical'},
    19: {'type': 'land', 'threat_level': 'critical'},
    20: {'type': 'loadmodule', 'threat_level': 'critical'},
    21: {'type': 'spy', 'threat_level': 'critical'},
    22: {'type': 'perl', 'threat_level': 'critical'}
}


def preprocess_new_data(new_data):
    # Preprocess the incoming data
    X_processed, y_processed= preprocess_all(new_data)

    return X_processed

def detect_anomalies(preprocessed_data):
    predictions = loaded_model.predict(preprocessed_data)
    return np.argmax(predictions, axis=1)

def trigger_alert(detected_anomalies):
    detected_attacks = [attacks_dict.get(idx, {'type': 'Unknown', 'threat_level': 'Unknown'}) for idx in detected_anomalies]

    if any(attack['type'] != 'normal' for attack in detected_attacks):
        for attack in detected_attacks:
            if attack['type'] != 'normal':
                print(f"ALERT: Detected {attack['type']} with threat level: {attack['threat_level']}")
    else:
        print("No anomalies detected.")

# Continuous data monitoring loop
while True:
    new_data = 'KDDTest+.txt'
    preprocessed_data = preprocess_new_data(new_data)
    detected_anomalies = detect_anomalies(preprocessed_data)
    trigger_alert(detected_anomalies)
