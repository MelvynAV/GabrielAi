# GabrielAI: Phishing Detection using Supervised Learning

### 🔗 Demo: [View Live Prototype (v1.0)](https://gabrielaiv1.streamlit.app/)

## 🎓 Project Abstract
As a 3rd-year Computer Science student intersted in specialzing Cybersecurity and AI/ML (uOttawa), I developed this project to explore the practical application of **Machine Learning (ML)** in threat detection.

The core objective was to move away from static "blacklist" approaches and instead build a heuristic engine capable of identifying malicious URLs based on their structural and lexical properties. This repository contains the source code for the data processing pipeline, the model training script, and the web interface.

## 🔬 Methodology & Feature Engineering

One of the key learnings from this project was that raw text cannot be fed directly into an algorithm. I had to implement a **Feature Extraction** phase to convert URLs into numerical vectors representing specific indicators of compromise (IOCs).

I focused on the following lexical features, implemented in `feature_extraction.py`:

* **IP Address Usage:** Phishing attacks often use direct IP access to bypass DNS blocklists.
* **URL Depth & Length:** Malicious payloads are frequently hidden deep within directory structures to obfuscate the domain.
* **Redirection & Obfuscation:** Detection of symbols like `@` (used to trick browser authentication parsing) or excessive subdomains.
* **Protocol Analysis:** Checking for HTTPS (though I learned that HTTPS is no longer a guarantee of safety, it remains a relevant feature in the weighted decision tree).

## 🤖 Model Selection

For the classification engine, I chose the **Random Forest** algorithm (via `scikit-learn`).

* **Reasoning:** Unlike a single Decision Tree which is prone to overfitting, Random Forest aggregates the votes of multiple trees. This is particularly effective for tabular data where the boundary between "safe" and "malicious" is not linear.
* **Current Metrics:** The model was trained on a balanced subset of data to ensure it doesn't bias towards the majority class (Safe sites).

## 🛠️ Technology Stack

* **Python 3.10+**: Core logic.
* **Scikit-Learn**: Model training and evaluation.
* **Pandas/NumPy**: Data manipulation and vectorization.
* **Streamlit**: Utilized for rapid deployment of the frontend to visualize the model's decision-making process in real-time.

## 📚 Key Takeaways & Challenges

Developing GabrielAI highlighted several challenges in AI-driven security:

1.  **Data Quality:** I realized that the accuracy of the model is heavily dependent on the diversity of the training set. A model trained only on old phishing links fails to detect new patterns.
2.  **False Positives:** Striking a balance between sensitivity (catching all threats) and precision (not blocking legitimate sites) is the hardest part of tuning the model.
3.  **Deployment:** I gained experience in serializing models (`pickle`) and deploying a Python application to a cloud environment (Streamlit Community Cloud).

## 🚀 Future Work (v2.0 Roadmap)

This project is currently in its Alpha stage (`v1.0`). To improve its reliability for a real-world context, I plan to:

* [ ] Increase the dataset size from 2k to 50k+ entries.
* [ ] Implement **WHOIS lookups** to calculate domain age (a critical feature for detecting "burner" domains).
* [ ] Experiment with **XGBoost** to compare performance with Random Forest.

---

Author: Melvyn Avoa 