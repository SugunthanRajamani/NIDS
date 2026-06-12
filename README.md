# NIDS
# 🛡️ Network Intrusion Detection System (IDS)

A machine learning-powered backend system that detects network intrusions in real time using a Flask REST API and a trained Random Forest classifier.

---

## 📌 Overview

This project is a full-stack intrusion detection system that classifies network traffic into 9 attack categories with **90.4% accuracy** at sub-200ms response latency. It combines machine learning, REST API design, and a live dashboard for real-time monitoring.

---

## 🚀 Features

Real-time network traffic classification via REST API
Random Forest ML model trained on 257K+ samples (UNSW-NB15 dataset)
SQLite alert-logging with indexed tables for fast querying across 10K+ events
Live Flask web dashboard to visualise detections
Sub-200ms end-to-end API response latency


## 🧠 Tech Stack

| Layer | Technology |
|---|---|
| Backend | Python, Flask |
| Machine Learning | scikit-learn, Random Forest |
| Data Processing | pandas, NumPy |
| Database | SQLite |
| Dataset | UNSW-NB15 (257K samples, 45 features) |
| API | REST API (JSON request/response) |

---

## 📁 Project Structure

```
ids_system/
├── app.py                  # Flask app & API routes
├── model/
│   ├── train.py            # Model training script
│   ├── model.pkl           # Trained Random Forest model
│   └── preprocessor.pkl    # Feature preprocessing pipeline
├── database/
│   └── alerts.db           # SQLite alert log database
├── templates/
│   └── dashboard.html      # Live detection dashboard
├── static/
│   └── style.css
├── requirements.txt
└── README.md
```

---

## 📡 API Endpoints

### `POST /predict`
Classifies network traffic as normal or an attack type.

**Request Body:**
```json
{
  "features": [0.5, 1.2, 0.0, ...]
}
```

**Response:**
```json
{
  "prediction": "DoS",
  "confidence": 0.94,
  "timestamp": "2026-04-12T10:23:01Z"
}
```

### `GET /alerts`
Returns recent alert logs from the SQLite database.

### `GET /dashboard`
Opens the live web dashboard for real-time visualisation.

---

## ⚙️ Setup & Installation

### 1. Clone the repository
```bash
git clone https://github.com/sugunthan-r/ids-system.git
cd ids-system
```

### 2. Install dependencies
```bash
pip install -r requirements.txt
```

### 3. Train the model (optional — pre-trained model included)
```bash
python model/train.py
```

### 4. Run the Flask app
```bash
python app.py
```

### 5. Access the dashboard
Open your browser and go to: `http://localhost:5000/dashboard`

---

## 📊 Model Performance

| Metric | Value |
|---|---|
| Dataset | UNSW-NB15 |
| Samples | 257,000+ |
| Features | 45 |
| Algorithm | Random Forest |
| Accuracy | **90.4%** |
| Attack Classes | 9 |
| API Latency | < 200ms |

---

## 🗂️ Dataset

This project uses the [UNSW-NB15 dataset](https://research.unsw.edu.au/projects/unsw-nb15-dataset) — a comprehensive network intrusion dataset with 9 attack categories.

---

## 🔮 Future Improvements

- [ ] Add user authentication for the dashboard
- [ ] Support real-time packet capture via `scapy`
- [ ] Deploy to cloud (AWS / Render)
- [ ] Add email/SMS alerting for high-severity detections
- [ ] Improve model accuracy with deep learning (LSTM)

---

## 👨‍💻 Author

**Sugunthan R**  
Backend Developer | Python • Flask • ML  
📧 sugusugu1110@gmail.com  
