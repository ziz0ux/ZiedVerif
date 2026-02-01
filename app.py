import streamlit as st
import hashlib
import requests
from PIL import Image

# --- CONFIGURATION API ---
# J'ai intégré tes clés que tu as générées
API_USER = '166866727'
API_SECRET = 'QNCDfaqptbXbUogsxZkvqFKFwhWS7Kii'

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

from fpdf import FPDF
import datetime

def create_pdf_report(hash_id, score, verdict):
    pdf = FPDF()
    pdf.add_page()
    
    # En-tête
    pdf.set_font("Arial", 'B', 16)
    pdf.cell(200, 10, txt="CERTIFICAT D'AUTHENTICITÉ ZiedVERIF", ln=True, align='C')
    pdf.ln(10)
    
    # Détails
    pdf.set_font("Arial", size=12)
    date_now = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    pdf.cell(200, 10, txt=f"Date de l'analyse : {date_now}", ln=True)
    pdf.cell(200, 10, txt=f"ID Unique du fichier (Hash) :", ln=True)
    pdf.set_font("Courier", size=10)
    pdf.cell(200, 10, txt=f"{hash_id}", ln=True)
    
    pdf.ln(10)
    pdf.set_font("Arial", 'B', 14)
    pdf.cell(200, 10, txt=f"SCORE DE FIABILITÉ : {score}%", ln=True)
    pdf.cell(200, 10, txt=f"VERDICT : {verdict}", ln=True)
    
    pdf.ln(20)
    pdf.set_font("Arial", 'I', 10)
    pdf.multi_cell(0, 10, txt="Ce document atteste que le fichier a été analysé par les algorithmes de détection de GamoudiVerif. L'empreinte numérique garantit que le rapport correspond exactement au fichier soumis.")
    
    return pdf.output(dest='S').encode('latin-1')




# --- INTERFACE ---
st.set_page_config(page_title="ZiedVerif IA", page_icon="🛡️")
st.title("🛡️ ZiedVerif IA : Certification de Réalité")
st.write("Vérifiez l'origine d'une image et générez une empreinte de confiance.")

uploaded_file = st.file_uploader("Analysez l'authenticité d'une image", type=["jpg", "jpeg", "png"])

if uploaded_file:
    # 1. Calcul du Hash
    hash_id = get_file_hash(uploaded_file)
    st.image(uploaded_file, width=300)
    
    # 2. Bouton pour lancer l'analyse (pour ne pas consommer tes crédits API inutilement)
    if st.button("Lancer l'analyse profonde"):
        with st.spinner('Analyse des pixels en cours par GamoudiVerif...'):
            result = check_deepfake(uploaded_file)
            
            if result.get('status') == 'success':
                # Le score de probabilité de Deepfake (0 à 1)
                prob = result['type']['deepfake']
                score_final = int((1 - prob) * 100)
                
                st.subheader(f"Score de Fiabilité : {score_final}%")
                
                if score_final > 80:
                    st.success("✅ Cette image semble authentique.")
                elif score_final > 40:
                    st.warning("⚠️ Prudence : Des traces de manipulation ont été détectées.")
                else:
                    st.error("❌ Alerte : Probabilité élevée d'image générée par IA !")
                    
                st.info(f"**Empreinte numérique (Hash) :** {hash_id}")
            else:
                st.error("Erreur de connexion à l'IA. Vérifiez vos crédits Sightengine.")


                # Créer le verdict pour le PDF
        verdict_text = "AUTHENTIQUE" if score_final > 80 else "SUSPECT"
        
        # Générer le PDF
        pdf_data = create_pdf_report(hash_id, score_final, verdict_text)
        
        st.download_button(
            label="📄 Télécharger le Certificat de Confiance",
            data=pdf_data,
            file_name=f"Certificat_{hash_id[:8]}.pdf",
            mime="application/pdf"
        )