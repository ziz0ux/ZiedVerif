import streamlit as st
import hashlib
import requests
from PIL import Image
from fpdf import FPDF
import datetime
import base64
import io
from pdf2image import convert_from_bytes

# --- 1. CONFIGURATION DES CLÉS API ---
API_USER_SIGHT = '166866727'
API_SECRET_SIGHT = 'QNCDfaqptbXbUogsxZkvqFKFwhWS7Kii'
VT_API_KEY = '4e1852f8bf4c7dd379b0951b5302c99039c89a6a1a2e458caf60c6ef4b052f64' 
HIVE_API_KEY = 'HUpSfnDqivnrHLcU/j55OefZpbUIQp+i5+ePVQ==' 

# --- 2. CONFIGURATION DE LA PAGE ---
st.set_page_config(page_title="ZiedVerif Pro IA", page_icon="🛡️", layout="wide")

if 'credits' not in st.session_state:
    st.session_state.credits = 5

st.markdown("""
    <style>
    .stButton>button { width: 100%; border-radius: 8px; font-weight: bold; background-color: #007BFF; color: white; }
    .stDownloadButton>button { width: 100%; background-color: #28a745 !important; color: white !important; }
    [data-testid="stSidebar"] { background-color: #f8f9fa; border-right: 1px solid #e0e0e0; }
    .team-box { padding: 10px; background-color: #ffffff; border-radius: 5px; border-left: 5px solid #007BFF; margin-bottom: 10px; box-shadow: 2px 2px 5px rgba(0,0,0,0.05); }
    </style>
    """, unsafe_allow_html=True)

# --- 3. FONCTIONS TECHNIQUES ---

def get_file_hash(file):
    sha256_hash = hashlib.sha256()
    file.seek(0)
    content = file.read()
    sha256_hash.update(content)
    file.seek(0)
    return sha256_hash.hexdigest()

def convert_pdf_to_images(pdf_file):
    pdf_file.seek(0)
    images = convert_from_bytes(pdf_file.read(), dpi=300)
    pdf_file.seek(0)
    return images

def check_deepfake_sightengine(file):
    file.seek(0)
    files = {'media': file}
    data = {'models': 'deepfake', 'api_user': API_USER_SIGHT, 'api_secret': API_SECRET_SIGHT}
    try:
        response = requests.post('https://api.sightengine.com/1.0/check.json', files=files, data=data)
        return response.json()
    except: return None

def check_hive_ai(file):
    file.seek(0)
    url = "https://api.thehive.ai/api/v2/task/sync"
    headers = {"Authorization": f"token {HIVE_API_KEY}", "accept": "application/json"}
    data = {'model_variants': 'ai_generated_image_detection'}
    files = {'media': file}
    try:
        response = requests.post(url, headers=headers, data=data, files=files)
        if response.status_code == 200:
            classes = response.json()['status'][0]['response']['output'][0]['classes']
            for item in classes:
                if item['class'] == 'ai_generated': return item['score']
        return 0
    except: return 0

def check_document_fraud(file_bytes):
    url = "https://api.thehive.ai/api/v2/task/sync"
    headers = {"Authorization": f"token {HIVE_API_KEY}", "accept": "application/json"}
    data = {'model_variants': 'document_alteration_detection'}
    files = {'media': ('page.jpg', file_bytes, 'image/jpeg')}
    try:
        response = requests.post(url, headers=headers, data=data, files=files)
        if response.status_code == 200:
            return response.json()['status'][0]['response']['output'][0]['score']
        return 0
    except: return 0

def check_url_safety(url):
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"accept": "application/json", "x-apikey": VT_API_KEY}
    try:
        response = requests.get(api_url, headers=headers)
        if response.status_code == 200:
            return response.json()['data']['attributes']['last_analysis_stats']
        return None
    except: return None

def create_pdf_report(hash_id, score, verdict, type_analysed):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("helvetica", 'B', 16)
    pdf.cell(0, 15, txt=f"CERTIFICAT ZIEDVERIF - {type_analysed}", ln=True, align='C')
    pdf.ln(10)
    pdf.set_font("helvetica", size=12)
    pdf.cell(0, 10, txt=f"Date : {datetime.datetime.now().strftime('%d/%m/%Y %H:%M')}", ln=True)
    pdf.multi_cell(0, 10, txt=f"Empreinte Numérique : {hash_id}")
    pdf.ln(10)
    pdf.set_font("helvetica", 'B', 14)
    pdf.cell(0, 10, txt=f"VERDICT FINAL : {verdict}", ln=True)
    pdf.cell(0, 10, txt=f"SCORE DE FIABILITÉ : {score}%", ln=True)
    return bytes(pdf.output())

# --- 4. BARRE LATÉRALE ---
with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/shield.png", width=80)
    st.title("ZiedVerif Pro")
    st.metric("🛡️ Crédits restants", f"{st.session_state.credits} / 5")
    choice = st.radio("Navigation", ["Certification Image", "Certification Document", "Analyse Vidéo", "Sécurité Liens", "À propos"])
    st.divider()
    st.subheader("👥 L'Équipe")
    st.markdown("""
    <div class="team-box"><strong>Zied</strong><br><small>Vision & Stratégie IA</small></div>
    <div class="team-box"><strong>Walid</strong><br><small>Expert Cybersécurité</small></div>
    <div class="team-box"><strong>Mounir</strong><br><small>Architecture Système</small></div>
    """, unsafe_allow_html=True)

# --- 5. LOGIQUE DES ONGLETS ---

if choice == "Certification Document":
    st.title("📄 Certification Documentaire (PDF & Images)")
    doc_file = st.file_uploader("Importer le document...", type=["pdf", "jpg", "jpeg", "png"])
    if doc_file:
        if doc_file.type == "application/pdf":
            with st.spinner('Conversion du PDF...'):
                pages = convert_pdf_to_images(doc_file)
                st.info(f"PDF analysé : Page 1 sur {len(pages)}")
                img_byte_arr = io.BytesIO()
                pages[0].save(img_byte_arr, format='JPEG')
                image_to_analyze = img_byte_arr.getvalue()
                st.image(pages[0], width=400)
        else:
            image_to_analyze = doc_file.getvalue()
            st.image(doc_file, width=400)

        if st.session_state.credits > 0:
            if st.button("Lancer l'Audit Document"):
                st.session_state.credits -= 1
                with st.spinner('Analyse forensique...'):
                    fraud_score = check_document_fraud(image_to_analyze)
                    score_f = int(fraud_score * 100)
                    hash_id = get_file_hash(doc_file)
                    verdict = "DOCUMENT FALSIFIÉ" if score_f > 10 else "DOCUMENT CONFORME"
                    if score_f > 10: st.error(f"🚨 {verdict} ({score_f}%)")
                    else: st.success(f"🛡️ {verdict}")
                    pdf_rep = create_pdf_report(hash_id, 100-score_f, verdict, "DOCUMENT")
                    st.download_button("📥 Télécharger Certificat", data=pdf_rep, file_name="Certificat_Doc.pdf")

elif choice == "Certification Image":
    st.title("📸 Certification IA")
    uploaded_file = st.file_uploader("Importer une image...", type=["jpg", "jpeg", "png"])
    if uploaded_file and st.session_state.credits > 0:
        st.image(uploaded_file, width=300)
        if st.button("Lancer l'Audit Global"):
            st.session_state.credits -= 1
            with st.spinner('Analyse des pixels...'):
                score_h = int(check_hive_ai(uploaded_file) * 100)
                hash_id = get_file_hash(uploaded_file)
                verdict = "IA DÉTECTÉE" if score_h > 5 else "AUTHENTIQUE"
                if score_h > 5: st.error(f"🚨 {verdict} ({score_h}%)")
                else: st.success(f"🛡️ {verdict}")
                pdf_rep = create_pdf_report(hash_id, 100-score_h, verdict, "IMAGE")
                st.download_button("📥 Télécharger Certificat", data=pdf_rep, file_name="Certificat_Image.pdf")

elif choice == "Analyse Vidéo":
    st.title("🎬 Détection Deepfake Vidéo")
    video_file = st.file_uploader("Importer une vidéo...", type=["mp4", "mov", "avi"])
    if video_file and st.session_state.credits > 0:
        st.video(video_file)
        if st.button("Analyser la vidéo"):
            st.session_state.credits -= 1
            with st.spinner('Analyse faciale en cours...'):
                res = check_deepfake_sightengine(video_file)
                score = int(res.get('type', {}).get('deepfake', 0) * 100) if res else 0
                if score > 15: st.error(f"🚨 DEEPFAKE PROBABLE ({score}%)")
                else: st.success(f"✅ VIDÉO AUTHENTIQUE ({score}%)")

elif choice == "Sécurité Liens":
    st.title("🔗 Analyse de Liens (Anti-Phishing)")
    url_input = st.text_input("Collez l'URL suspecte ici :")
    if url_input and st.session_state.credits > 0:
        if st.button("Scanner l'URL"):
            st.session_state.credits -= 1
            with st.spinner('Vérification sur VirusTotal...'):
                stats = check_url_safety(url_input)
                if stats:
                    malicious = stats.get('malicious', 0)
                    suspicious = stats.get('suspicious', 0)
                    if malicious > 0 or suspicious > 0:
                        st.error(f"🚨 DANGER : {malicious} moteurs ont détecté ce lien comme malveillant.")
                    else:
                        st.success("✅ Aucun danger détecté pour cette URL.")
                else:
                    st.warning("Impossible d'analyser cette URL. Vérifiez le format.")

elif choice == "À propos":
    st.title("📖 L'Histoire de ZiedVerif")
    st.write("Trois experts unis pour restaurer la confiance dans le contenu numérique.")
    st.divider()
    col_z, col_w, col_m = st.columns(3)
    with col_z:
        st.subheader("🦁 Zied")
        st.write("**Vision & Stratégie IA**")
        st.caption("Expert en analyse de tendances, Zied définit la direction stratégique pour anticiper les nouveaux types de Deepfakes.")
    with col_w:
        st.subheader("🛡️ Walid")
        st.write("**Expert Cybersécurité**")
        st.caption("Gardien de l'intégrité, Walid assure l'intégration des protocoles de sécurité et la surveillance des menaces.")
    with col_m:
        st.subheader("⚙️ Mounir")
        st.write("**Architecture Système**")
        st.caption("Maître d'œuvre technique, Mounir optimise les flux API et garantit la stabilité de l'infrastructure.")
    st.divider()
    st.markdown("### 💡 Notre Mission\nCréer un **bouclier numérique** universel contre la fraude et la désinformation.")

st.divider()
st.caption("© 2026 ZiedVerif Pro - Version 2.8 Finale")