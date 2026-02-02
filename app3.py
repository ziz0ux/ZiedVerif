import streamlit as st
import hashlib
import requests
from PIL import Image
from fpdf import FPDF
import datetime
import base64
import io
import time
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

# Style CSS personnalisé
st.markdown("""
    <style>
    .stButton>button { width: 100%; border-radius: 8px; font-weight: bold; background-color: #007BFF; color: white; }
    .stDownloadButton>button { width: 100%; background-color: #28a745 !important; color: white !important; }
    [data-testid="stSidebar"] { background-color: #f8f9fa; border-right: 1px solid #e0e0e0; }
    .team-box { padding: 15px; background-color: #ffffff; border-radius: 10px; border-left: 5px solid #007BFF; margin-bottom: 10px; box-shadow: 2px 2px 5px rgba(0,0,0,0.05); }
    </style>
    """, unsafe_allow_html=True)

# --- 3. FONCTIONS TECHNIQUES ---

def get_file_hash(file):
    file.seek(0)
    content = file.read()
    sha256_hash = hashlib.sha256(content).hexdigest()
    file.seek(0)
    return sha256_hash

def convert_pdf_to_images(pdf_file):
    try:
        pdf_file.seek(0)
        images = convert_from_bytes(pdf_file.read(), dpi=300)
        pdf_file.seek(0)
        return images
    except Exception as e:
        st.error(f"Erreur technique Poppler : {e}")
        return None

def check_deepfake_sightengine(file):
    file.seek(0)
    files = {'media': file}
    data = {'models': 'deepfake', 'api_user': API_USER_SIGHT, 'api_secret': API_SECRET_SIGHT}
    try:
        response = requests.post('https://api.sightengine.com/1.0/check.json', files=files, data=data)
        return response.json()
    except: return None

def check_hive_ai(file, variant='ai_generated_image_detection'):
    file.seek(0)
    url = "https://api.thehive.ai/api/v2/task/sync"
    headers = {"Authorization": f"token {HIVE_API_KEY}", "accept": "application/json"}
    data = {'model_variants': variant}
    files = {'media': file}
    try:
        response = requests.post(url, headers=headers, data=data, files=files)
        if response.status_code == 200:
            return response.json()['status'][0]['response']['output'][0]['classes'][0]['score']
        return 0
    except: return 0

def check_document_fraud(file_bytes):
    url = "https://api.thehive.ai/api/v2/task/sync"
    headers = {"Authorization": f"token {HIVE_API_KEY}", "accept": "application/json"}
    data = {'model_variants': 'document_alteration_detection'}
    files = {'media': ('doc.jpg', file_bytes, 'image/jpeg')}
    try:
        response = requests.post(url, headers=headers, data=data, files=files)
        return response.json()['status'][0]['response']['output'][0]['score']
    except: return 0

def check_url_safety(url):
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        res = requests.get(api_url, headers=headers)
        return res.json()['data']['attributes']['last_analysis_stats'] if res.status_code == 200 else None
    except: return None

def create_pdf_report(hash_id, score, verdict, type_analysed):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("helvetica", 'B', 16)
    pdf.cell(0, 15, txt=f"CERTIFICAT ZIEDVERIF - {type_analysed}", ln=True, align='C')
    pdf.ln(10)
    pdf.set_font("helvetica", size=12)
    pdf.cell(0, 10, txt=f"Date : {datetime.datetime.now().strftime('%d/%m/%Y %H:%M')}", ln=True)
    pdf.multi_cell(0, 10, txt=f"Empreinte Numérique (SHA-256) : {hash_id}")
    pdf.ln(5)
    pdf.cell(0, 10, txt=f"Verdict Final : {verdict}", ln=True)
    pdf.cell(0, 10, txt=f"Score de Fiabilité : {score}%", ln=True)
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
    doc_file = st.file_uploader("Importer le document (PDF, JPG, PNG)...", type=["pdf", "jpg", "jpeg", "png"])
    if doc_file and st.session_state.credits > 0:
        if doc_file.type == "application/pdf":
            with st.spinner('Traitement du PDF...'):
                pages = convert_pdf_to_images(doc_file)
                if pages:
                    st.info(f"Document PDF détecté : {len(pages)} page(s). Analyse de la page 1.")
                    img_buf = io.BytesIO()
                    pages[0].save(img_buf, format='JPEG')
                    image_to_analyze = img_buf.getvalue()
                    st.image(pages[0], width=400, caption="Aperçu Page 1")
        else:
            image_to_analyze = doc_file.getvalue()
            st.image(doc_file, width=400)

        if st.button("Lancer l'Audit Document"):
            st.session_state.credits -= 1
            with st.spinner('Recherche de falsifications...'):
                fraud_score = check_document_fraud(image_to_analyze)
                score_f = int(fraud_score * 100)
                verdict = "DOCUMENT FALSIFIÉ" if score_f > 15 else "DOCUMENT CONFORME"
                if score_f > 15: st.error(f"🚨 {verdict} ({score_f}% d'altérations détectées)")
                else: st.success(f"🛡️ {verdict}")
                pdf_rep = create_pdf_report(get_file_hash(doc_file), 100-score_f, verdict, "DOCUMENT")
                st.download_button("📥 Télécharger le Certificat", data=pdf_rep, file_name="Certificat_Doc.pdf")

elif choice == "Certification Image":
    st.title("📸 Certification IA (Images)")
    img_file = st.file_uploader("Importer une image...", type=["jpg", "jpeg", "png"])
    if img_file and st.session_state.credits > 0:
        st.image(img_file, width=300)
        if st.button("Lancer l'Audit Image"):
            st.session_state.credits -= 1
            with st.spinner('Analyse des pixels...'):
                score_h = int(check_hive_ai(img_file) * 100)
                verdict = "GÉNÉRÉ PAR IA" if score_h > 10 else "IMAGE AUTHENTIQUE"
                if score_h > 10: st.error(f"🚨 {verdict} ({score_h}%)")
                else: st.success(f"🛡️ {verdict}")
                pdf_rep = create_pdf_report(get_file_hash(img_file), 100-score_h, verdict, "IMAGE")
                st.download_button("📥 Télécharger le Certificat", data=pdf_rep, file_name="Certificat_Image.pdf")

elif choice == "Analyse Vidéo":
    st.title("🎬 Détection Deepfake Vidéo")
    vid_file = st.file_uploader("Importer une vidéo...", type=["mp4", "mov", "avi"])
    if vid_file and st.session_state.credits > 0:
        st.video(vid_file)
        if st.button("Lancer l'Audit Profond (Double Analyse)"):
            prog = st.progress(0)
            status = st.empty()
            st.session_state.credits -= 1
            
            status.text("Analyse 1/2 : Biométrie faciale (Sightengine)...")
            res_s = check_deepfake_sightengine(vid_file)
            prog.progress(50)
            
            status.text("Analyse 2/2 : Signatures algorithmiques (Hive AI)...")
            score_h = int(check_hive_ai(vid_file, 'ai_generated_video_detection') * 100)
            prog.progress(100)
            
            score_s = int(res_s.get('type', {}).get('deepfake', 0) * 100) if res_s else 0
            final = max(score_s, score_h)
            
            st.divider()
            if final > 20: 
                st.error(f"🚨 CONTENU NON-AUTHENTIQUE ({final}%)")
                st.write(f"Détail : FaceSwap ({score_s}%) | Génération IA ({score_h}%)")
            else: 
                st.success(f"🛡️ VIDÉO AUTHENTIQUE (Score de confiance élevé)")
                st.balloons()
            time.sleep(2)
            status.empty()
            prog.empty()

elif choice == "Sécurité Liens":
    st.title("🔗 Analyse de Liens (Anti-Phishing)")
    url_in = st.text_input("Collez l'URL à vérifier :")
    if url_in and st.button("Scanner le lien"):
        st.session_state.credits -= 1
        with st.spinner('Vérification sur les bases de menaces...'):
            stats = check_url_safety(url_in)
            if stats and stats.get('malicious', 0) > 0: 
                st.error(f"🚨 DANGER : Lien détecté comme malveillant par {stats['malicious']} moteurs.")
            else: 
                st.success("✅ Aucun danger détecté pour ce lien.")

elif choice == "À propos":
    st.title("📖 L'Histoire de ZiedVerif")
    st.write("Trois experts unis pour restaurer la confiance dans le contenu numérique.")
    st.divider()
    col_z, col_w, col_m = st.columns(3)
    with col_z:
        st.subheader("🦁 Zied")
        st.write("**Vision & Stratégie IA**")
        st.caption("Expert en analyse de tendances, Zied définit la direction stratégique pour anticiper les nouveaux types de menaces.")
    with col_w:
        st.subheader("🛡️ Walid")
        st.write("**Expert Cybersécurité**")
        st.caption("Gardien de l'intégrité, Walid assure l'intégration des protocoles de sécurité et la surveillance des données.")
    with col_m:
        st.subheader("⚙️ Mounir")
        st.write("**Architecture Système**")
        st.caption("Maître d'œuvre technique, Mounir optimise les flux API et garantit la stabilité de l'infrastructure.")
    st.divider()
    st.markdown("### 💡 Notre Mission")
    st.info("Créer un **bouclier numérique** universel contre la fraude et la désinformation. ZiedVerif utilise les meilleures IA mondiales pour certifier la vérité.")
    st.success("Version 2.9 Gold - Système de Certification Certifié")

st.divider()
st.caption("© 2026 ZiedVerif Pro - Protections Numériques Avancées")