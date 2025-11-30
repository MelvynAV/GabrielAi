import streamlit as st
import pickle
import numpy as np
import os

# --- 1. DEPENDENCY CHECK ---
try:
    from feature_extraction import extract_features
except ImportError:
    st.error("❌ Critical Error: 'feature_extraction.py' not found. Please ensure it is in the same directory.")
    st.stop()

# --- 2. PAGE CONFIGURATION ---
st.set_page_config(
    page_title="GabrielAI - Phishing Detection",
    page_icon="🛡️",
    layout="centered"
)

# --- 3. ANGELIC THEME (CSS) ---
st.markdown("""
<style>
    /* BACKGROUND: Blue Sky & Clouds */
    .stApp {
        background-image: url("https://images.unsplash.com/photo-1504608524841-42fe6f032b4b?q=80&w=3165&auto=format&fit=crop");
        background-size: cover;
        background-position: center;
        background-attachment: fixed;
    }

    /* MAIN CONTAINER: White Glass Effect */
    .main .block-container {
        background-color: rgba(255, 255, 255, 0.92); /* White with slight transparency */
        padding: 3rem;
        border-radius: 20px;
        box-shadow: 0 10px 30px rgba(0, 0, 0, 0.2);
        margin-top: 1rem;
    }

    /* TITLES */
    h1 {
        color: #B8860B; /* Dark Gold */
        text-align: center;
        font-family: 'Helvetica Neue', sans-serif;
        text-transform: uppercase;
        letter-spacing: 1px;
    }
    
    h3 {
        color: #555;
        font-weight: 300;
        font-style: italic;
    }

    /* BUTTON STYLING */
    div.stButton > button {
        background: linear-gradient(90deg, #d4af37 0%, #f7e98e 100%);
        color: #4a3b2a;
        border: none;
        padding: 10px 20px;
        border-radius: 50px;
        font-size: 18px;
        font-weight: bold;
        box-shadow: 0 4px 10px rgba(212, 175, 55, 0.3);
        width: 100%;
        transition: all 0.3s;
    }
    div.stButton > button:hover {
        transform: scale(1.02);
        box-shadow: 0 6px 15px rgba(212, 175, 55, 0.5);
    }
    
    /* INPUT FIELD */
    .stTextInput > div > div > input {
        border-radius: 50px;
        padding-left: 20px;
        border: 1px solid #d4af37;
    }
</style>
""", unsafe_allow_html=True)

# --- 4. LOAD MODEL ---
try:
    with open('gabriel_model.pkl', 'rb') as file:
        model = pickle.load(file)
except FileNotFoundError:
    st.error("⚠️ Model not found. Please run 'train_model.py' first.")
    st.stop()

# --- 5. VISUAL HEADER (ARCHANGEL GABRIEL) ---
# Using columns to center the image perfectly
col_left, col_image, col_right = st.columns([1, 2, 1])

with col_image:
    # HYBRID LOADING STRATEGY
    if os.path.exists("angel.jpg"):
        # Priority 1: Local Image (Fastest & Safest)
        st.image("angel.jpg", caption="Guardian of the Network", use_container_width=True)
    else:
        # Priority 2: Reliable Backup from Unsplash (If you haven't downloaded angel.jpg yet)
        st.image(
            "https://images.unsplash.com/photo-1542259681-d41907cb3874?q=80&w=600&auto=format&fit=crop",
            caption="Archangel Gabriel - Guardian of the Message",
            use_container_width=True
        )

# --- 6. TITLE & INTRO ---
st.markdown("<h1>Gabriel AI</h1>", unsafe_allow_html=True)
st.markdown(
    "<h3 style='text-align: center;'>The Digital Archangel guarding your network.</h3>", 
    unsafe_allow_html=True
)
st.markdown(
    "<p style='text-align: center; color: #666;'>This AI engine analyzes URL structures to detect phishing threats in real-time.</p>", 
    unsafe_allow_html=True
)
st.markdown("---")

# --- 7. INPUT AREA ---
st.markdown("### 🔍 Analyze a Link")
url_input = st.text_input("URL", placeholder="Paste the suspicious URL here (e.g., http://paypal-update-security.com...)", label_visibility="collapsed")
analyze_btn = st.button("🛡️ ANALYZE URL")

# --- 8. DETECTION LOGIC ---
if analyze_btn:
    if not url_input:
        st.warning("⚠️ Please provide a URL to analyze.")
    else:
        with st.spinner("Analyzing URL structure..."):
            try:
                # 1. Feature Extraction
                features = extract_features(url_input)
                
                # 2. Prediction
                features_array = np.array(features).reshape(1, -1)
                prediction = model.predict(features_array)[0]
                probability = model.predict_proba(features_array)
                
                # 3. Display Results
                st.markdown("---")
                
                if prediction == 1:
                    # CASE: PHISHING (BAD)
                    st.markdown("""
                    <div style='background-color: #ffe6e6; padding: 20px; border-radius: 10px; border-left: 6px solid #ff4d4d; text-align: center;'>
                        <h2 style='color: #cc0000; margin:0;'>👹 THREAT DETECTED</h2>
                        <p style='color: #a30000; font-size: 1.1em;'>This URL shows strong signs of Phishing.</p>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    confidence = probability[0][1] * 100
                    st.metric("Risk Level", f"{confidence:.2f}%", delta="HIGH RISK")
                    st.error("RECOMMENDATION: Do NOT click. Block this domain.")

                else:
                    # CASE: SAFE (GOOD)
                    st.markdown("""
                    <div style='background-color: #e6f7ff; padding: 20px; border-radius: 10px; border-left: 6px solid #00bfff; text-align: center;'>
                        <h2 style='color: #007acc; margin:0;'>🛡️ SAFE LINK</h2>
                        <p style='color: #005f73; font-size: 1.1em;'>The URL structure appears legitimate.</p>
                    </div>
                    """, unsafe_allow_html=True)
                    
                    confidence = probability[0][0] * 100
                    st.metric("Safety Confidence", f"{confidence:.2f}%", delta="SAFE")
                    st.success("RECOMMENDATION: You may proceed.")

                # Technical Details (Expandable)
                with st.expander("📜 View Technical Report (Extracted Features)"):
                    st.write("GabrielAI extracted the following indicators:")
                    c1, c2 = st.columns(2)
                    with c1:
                        st.json({
                            "IP Address Detected": bool(features[0]),
                            "URL Length": features[1],
                            "URL Depth": features[2]
                        })
                    with c2:
                        st.json({
                            "Symbol '@'": features[3],
                            "Dots count (.)": features[4],
                            "HTTPS Protocol": bool(features[5])
                        })

            except Exception as e:
                st.error(f"Analysis failed: {e}")