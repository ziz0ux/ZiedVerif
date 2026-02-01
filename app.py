import streamlit as st
import hashlib
import requests
from PIL import Image
from fpdf import FPDF
import datetime

# --- CONFIGURATION API ---
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

def create_pdf_report(hash_id, score, verdict):
    pdf = FPDF()
    pdf.add_page()
    
    # Titre
    pdf.set_font("helvetica", 'B', 16)
    pdf.cell(0, 10, txt="CERTIFICAT D'AUTHENTICITE ZIEDIVERIF", ln=True, align='C')
    pdf.ln(10)
    
    # Infos
    pdf.set_font("helvetica", size=12)
    date_now = datetime.datetime.now().strftime("%d/%m/%Y %H:%M:%S")
    pdf.cell(0, 10, txt=f"Date : {date_now}", ln=True)
    
    pdf.set_font("courier", size=10)
    pdf.multi_cell(0, 10, txt=f"ID Unique (Hash) : {hash_id}")
    
    pdf.ln(5)
    pdf.set_font("helvetica", 'B', 14)
    pdf.cell(0, 10, txt=f"SCORE DE FIABILITE : {score}%", ln=True)
    pdf.cell(0, 10, txt=f"VERDICT : {verdict}", ln=True)
    
    # LA CORRECTION MAGIQUE : on transforme le bytearray en bytes
    return bytes(pdf.output())

# --- INTERFACE ---
st.set_page_config(page_title="ZiedVerif IA", page_icon="🛡️")
st.title("🛡️ ZiedVerif IA : Certification de Réalité")
st.write("Vérifiez l'origine d'une image et générez une empreinte de confiance.")

uploaded_file = st.file_uploader("Analysez l'authenticité d'une image", type=["jpg", "jpeg", "png"])

if uploaded_file:
    hash_id = get_file_hash(uploaded_file)
    st.image(uploaded_file, width=300)
    
    if st.button("Lancer l'analyse profonde"):
        with st.spinner('Analyse des pixels en cours par ZiedVerif...'):
            result = check_deepfake(uploaded_file)
            
            if result.get('status') == 'success':
                prob = result['type']['deepfake']
                score_final = int((1 - prob) * 100)
                
                st.subheader(f"Score de Fiabilité : {score_final}%")
                
                if score_final > 80:
                    verdict_text = "AUTHENTIQUE"
                    st.success(f"✅ Cette image semble {verdict_text}.")
                elif score_final > 40:
                    verdict_text = "SUSPECT"
                    st.warning(f"⚠️ Prudence : Des traces de manipulation ont été détectées.")
                else:
                    verdict_text = "DEEPFAKE"
                    st.error(f"❌ Alerte : Probabilité élevée d'image générée par IA !")
                
                st.info(f"**Empreinte numérique (Hash) :** {hash_id}")

                # LE BOUTON EST MAINTENANT BIEN DANS LE BLOC DE RÉUSSITE
                pdf_bytes = create_pdf_report(hash_id, score_final, verdict_text)
                
                st.download_button(
                    label="📄 Télécharger le Certificat Officiel",
                    data=pdf_bytes,
                    file_name=f"Certificat_{hash_id[:8]}.pdf",
                    mime="application/pdf"
                )
            else:
                st.error("Erreur de connexion à l'IA. Vérifiez vos crédits.")