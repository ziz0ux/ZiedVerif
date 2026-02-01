import streamlit as st
import hashlib
import requests
from PIL import Image
from fpdf import FPDF
import datetime

# --- CONFIGURATION API ---
API_USER = '166866727'
API_SECRET = 'QNCDfaqptbXbUogsxZkvqFKFwhWS7Kii'

# --- STYLE PERSONNALISÉ (CSS) ---
st.set_page_config(page_title="ZiedVerif IA", page_icon="🛡️")

st.markdown("""
    <style>
    /* Style pour le bouton d'analyse (Bleu) */
    .stButton>button {
        width: 100%;
        border-radius: 8px;
        height: 3em;
        background-color: #007BFF;
        color: white;
        border: none;
        font-weight: bold;
        transition: 0.3s;
    }
    .stButton>button:hover {
        background-color: #0056b3;
        border: 1px solid white;
    }
    
    /* Style pour le bouton de téléchargement (Vert) */
    .stDownloadButton>button {
        width: 100%;
        background-color: #28a745 !important;
        color: white !important;
        border-radius: 8px;
        height: 3em;
        font-weight: bold;
        border: none;
    }
    .stDownloadButton>button:hover {
        background-color: #218838 !important;
    }
    </style>
    """, unsafe_allow_html=True)

# --- FONCTIONS TECHNIQUES ---
def get_file_hash(file):
    sha256_hash = hashlib.sha256()
    file.seek(0)
    for byte_block in iter(lambda: file.read(4096), b""):
        sha256_hash.update(byte_block)
    return sha256_hash.hexdigest()

def check_deepfake(file):
    file.seek(0)
    files = {'media': file}
    data = {
        'models': 'deepfake',
        'api_user': API_USER,
        'api_secret': API_SECRET
    }
    try:
        response = requests.post('https://api.sightengine.com/1.0/check.json', files=files, data=data)
        return response.json()
    except Exception as e:
        return {"status": "error", "message": str(e)}

def create_pdf_report(hash_id, score, verdict):
    pdf = FPDF()
    pdf.add_page()
    
    # En-tête
    pdf.set_font("helvetica", 'B', 16)
    pdf.cell(0, 15, txt="CERTIFICAT D'AUTHENTICITE ZIEDVERIF IA", ln=True, align='C')
    pdf.ln(10)
    
    # Informations de l'analyse
    pdf.set_font("helvetica", size=12)
    date_now = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    pdf.cell(0, 10, txt=f"Date de l'analyse : {date_now}", ln=True)
    
    pdf.ln(5)
    pdf.set_font("helvetica", 'B', 12)
    pdf.cell(0, 10, txt="Identifiant numerique du fichier (Hash) :", ln=True)
    pdf.set_font("courier", size=10)
    pdf.multi_cell(0, 10, txt=hash_id)
    
    pdf.ln(10)
    pdf.set_font("helvetica", 'B', 14)
    pdf.cell(0, 10, txt=f"RESULTAT : {verdict}", ln=True)
    pdf.cell(0, 10, txt=f"INDICE DE FIABILITE : {score}%", ln=True)
    
    pdf.ln(20)
    pdf.set_font("helvetica", 'I', 10)
    pdf.multi_cell(0, 10, txt="Ce document officiel atteste que l'image a ete soumise a une analyse de structure de pixels par IA. ZiedVerif garantit l'integrite du rapport lie a ce Hash unique.")
    
    return bytes(pdf.output())

# --- INTERFACE UTILISATEUR (LANDING PAGE) ---
st.title("🛡️ ZiedVerif IA")
st.subheader("La vérité derrière chaque pixel.")
st.subheader("author : Zied Ayachi, Walid Gamoudi, Mounir Khanfir.")

st.markdown("""
**Ne laissez plus le doute s'installer.** ZiedVerif analyse les images pour détecter les manipulations par Intelligence Artificielle et Deepfakes.
""")

col1, col2, col3 = st.columns(3)
with col1:
    st.write("🔍 **Analyse**")
    st.caption("Détection neuronale")
with col2:
    st.write("🔐 **Hash**")
    st.caption("Empreinte unique")
with col3:
    st.write("📄 **Certificat**")
    st.caption("Preuve PDF")

st.divider()

# --- ZONE DE TELECHARGEMENT ---
uploaded_file = st.file_uploader("Déposez l'image à certifier", type=["jpg", "jpeg", "png"])

if uploaded_file:
    hash_id = get_file_hash(uploaded_file)
    st.image(uploaded_file, width=300, caption="Fichier prêt pour analyse")
    
    if st.button("Lancer l'analyse de réalité"):
        with st.spinner('Analyse des artefacts IA en cours...'):
            result = check_deepfake(uploaded_file)
            
            if result.get('status') == 'success':
                prob = result['type']['deepfake']
                score_final = int((1 - prob) * 100)
                
                st.subheader(f"Score de Fiabilité : {score_final}%")
                
                if score_final > 80:
                    verdict = "AUTHENTIQUE"
                    st.success(f"✅ ANALYSE : Cette image semble {verdict}.")
                elif score_final > 40:
                    verdict = "SUSPECT"
                    st.warning(f"⚠️ PRUDENCE : Traces de manipulation détectées.")
                else:
                    verdict = "DEEPFAKE"
                    st.error(f"❌ ALERTE : Image probablement générée par IA.")
                
                st.info(f"**ID Numérique :** `{hash_id}`")

                # Génération et bouton PDF
                pdf_data = create_pdf_report(hash_id, score_final, verdict)
                st.download_button(
                    label="📄 Télécharger le Certificat de Confiance",
                    data=pdf_data,
                    file_name=f"Certificat_ZiedVerif_{hash_id[:8]}.pdf",
                    mime="application/pdf"
                )
            else:
                st.error("L'IA est momentanément indisponible. Vérifiez vos crédits API.")

st.divider()
st.caption("© 2026 ZiedVerif IA - Protection de l'intégrité numérique.")