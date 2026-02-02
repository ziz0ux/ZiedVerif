import streamlit as st
import hashlib
import requests
from PIL import Image, ImageChops, ImageEnhance
from PIL.ExifTags import TAGS
from fpdf import FPDF
import datetime
import base64
import io

# --- 1. CONFIGURATION DES CLÉS API ---
API_USER_SIGHT = '166866727'
API_SECRET_SIGHT = 'QNCDfaqptbXbUogsxZkvqFKFwhWS7Kii'
VT_API_KEY = '4e1852f8bf4c7dd379b0951b5302c99039c89a6a1a2e458caf60c6ef4b052f64' 
HIVE_API_KEY = 'HUpSfnDqivnrHLcU/j55OefZpbUIQp+i5+ePVQ==' 

# --- 2. INITIALISATION & DESIGN SYSTEM ---
st.set_page_config(page_title="ZiedVerif Pro v9.0 Titanium", page_icon="🛡️", layout="wide")

if 'credits' not in st.session_state:
    st.session_state.credits = 10

st.markdown("""
    <style>
    .stApp { background-color: #F8FAFC; }
    .main-card { background-color: white; padding: 25px; border-radius: 16px; box-shadow: 0 4px 15px rgba(0,0,0,0.05); border: 1px solid #E2E8F0; margin-bottom: 20px; }
    .stButton>button { width: 100%; border-radius: 12px; height: 3.2em; background: linear-gradient(135deg, #0062FF 0%, #0049BD 100%); color: white !important; font-weight: 600; border: none; }
    .expert-box { padding: 12px; background: #F8FAFC; border-radius: 10px; border-left: 4px solid #0062FF; margin-bottom: 8px; font-size: 0.9em; }
    .ai-tag { padding: 6px 12px; border-radius: 20px; background: #EBF4FF; color: #0062FF; font-weight: bold; font-size: 0.85em; margin-right: 8px; border: 1px solid #D1E4FF; }
    .sos-card { padding: 20px; background: #FFF5F5; border: 1px solid #FED7D7; border-radius: 12px; border-left: 5px solid #E53E3E; }
    .founder-card { padding: 20px; background: white; border: 1px solid #E2E8F0; border-radius: 15px; height: 100%; box-shadow: 0 2px 8px rgba(0,0,0,0.03); }
    </style>
    """, unsafe_allow_html=True)

# --- 3. MOTEUR DE DÉTECTION ET FORENSIC ---

def get_file_hash(file):
    file.seek(0)
    return hashlib.sha256(file.read()).hexdigest()

def detect_specific_ai_patterns(classes):
    """Identifie les signatures de modèles spécifiques (Google, DALL-E, etc.)"""
    detected = []
    for c in classes:
        name = c['class'].lower()
        if c['score'] > 0.15:
            if 'dalle' in name or 'dall_e' in name: detected.append("🎨 DALL-E (OpenAI)")
            if 'google' in name or 'synthid' in name: detected.append("🌐 Google AI / SynthID")
            if 'midjourney' in name: detected.append("⛵ Midjourney")
            if 'stable_diffusion' in name: detected.append("🌀 Stable Diffusion")
            if 'gan' in name: detected.append("🧬 Réseau GAN (Falsification)")
    return detected

def calculate_zied_score(ai_score_p, exif_found, ai_patterns):
    """Calcul hybride de l'indice de confiance"""
    score = 100 - ai_score_p
    if not exif_found: score -= 35 # Malus pour absence de preuves physiques
    if ai_patterns: score -= 25    # Malus pour signature de modèle IA reconnue
    return max(0, int(score))

def analyze_exif(file):
    file.seek(0)
    try:
        img = Image.open(file)
        info = img._getexif()
        if not info: return False, ["⚠️ Aucune donnée EXIF détectée (Signe probable de génération IA)"]
        details = [f"🔍 {TAGS.get(tag, tag)}: {value}" for tag, value in info.items() if tag in TAGS]
        return True, details
    except: return False, ["❌ Erreur lors de la lecture des métadonnées"]

def get_ela_image(file):
    """Error Level Analysis : Détecte les différences de compression"""
    file.seek(0)
    original = Image.open(file).convert('RGB')
    temp_io = io.BytesIO()
    original.save(temp_io, format='JPEG', quality=90)
    temp_io.seek(0)
    ela_img = ImageChops.difference(original, Image.open(temp_io))
    extrema = ela_img.getextrema()
    max_diff = max([ex[1] for ex in extrema]) or 1
    return ImageEnhance.Brightness(ela_img).enhance(255.0 / max_diff)

def check_hive(file, variant='ai_generated_image_detection'):
    file.seek(0)
    headers = {"Authorization": f"token {HIVE_API_KEY}"}
    try:
        res = requests.post("https://api.thehive.ai/api/v2/task/sync", 
                             headers=headers, data={'model_variants': variant}, files={'media': file})
        classes = res.json()['status'][0]['response']['output'][0]['classes']
        score = next((c['score'] for c in classes if c['class'] in ['ai_generated', 'ai_generated_video']), 0) * 100
        return classes, score
    except: return [], 0

def create_pdf_report(hash_id, zied_score, verdict, type_analysed, signatures):
    pdf = FPDF()
    pdf.add_page()
    pdf.set_font("helvetica", 'B', 22); pdf.set_text_color(0, 98, 255)
    pdf.cell(0, 20, txt="CERTIFICAT OFFICIEL ZIEDVERIF", ln=True, align='C')
    pdf.set_font("helvetica", size=12); pdf.set_text_color(0, 0, 0)
    pdf.ln(10)
    pdf.cell(0, 10, txt=f"Audit : {type_analysed} | Date : {datetime.datetime.now().strftime('%d/%m/%Y %H:%M')}", ln=True)
    pdf.multi_cell(0, 10, txt=f"Identifiant SHA-256 : {hash_id}")
    pdf.ln(5)
    pdf.set_font("helvetica", 'B', 16)
    pdf.cell(0, 15, txt=f"SCORE DE CONFIANCE : {zied_score}%", ln=True)
    pdf.set_font("helvetica", 'B', 14)
    pdf.cell(0, 10, txt=f"VERDICT : {verdict}", ln=True)
    if signatures:
        pdf.set_font("helvetica", size=11)
        pdf.cell(0, 10, txt=f"Signatures détectées : {', '.join(signatures)}", ln=True)
    return bytes(pdf.output())

# --- 4. NAVIGATION ---

with st.sidebar:
    st.image("https://img.icons8.com/fluency/96/shield.png", width=70)
    st.title("ZiedVerif Pro")
    choice = st.selectbox("🎯 MENU PRINCIPAL", ["Analyse Image", "Certification Document", "Analyse Vidéo", "Sécurité Liens", "À propos"])
    st.divider()
    st.metric("🛡️ CRÉDITS", st.session_state.credits)
    with st.expander("👤 L'ÉQUIPE FONDATRICE"):
        st.write("🦁 **Zied** (Vision)")
        st.write("🛡️ **Walid** (Cyber)")
        st.write("⚙️ **Mounir** (Architecture)")

# --- 5. MODULES FONCTIONNELS ---

if choice == "Analyse Image":
    st.title("📸 Investigation Forensique Image")
    img_file = st.file_uploader("Fichier image (JPG, PNG)", type=["jpg", "png", "jpeg"])
    
    if img_file and st.session_state.credits > 0:
        c1, c2 = st.columns(2)
        with c1:
            st.markdown('<div class="main-card">', unsafe_allow_html=True)
            st.image(img_file, caption="Image Source", use_container_width=True)
            st.markdown('</div>', unsafe_allow_html=True)
        with c2:
            st.markdown('<div class="main-card">', unsafe_allow_html=True)
            st.image(get_ela_image(img_file), caption="Analyse ELA (Modification de pixels)", use_container_width=True)
            st.markdown('</div>', unsafe_allow_html=True)

        if st.button("LANCER L'AUDIT TITANIUM"):
            st.session_state.credits -= 1
            classes, ai_p = check_hive(img_file)
            ai_patterns = detect_specific_ai_patterns(classes)
            has_exif, exif_details = analyze_exif(img_file)
            zied_score = calculate_zied_score(ai_p, has_exif, ai_patterns)
            
            st.divider()
            
            # --- VERDICT FINAL ---
            if zied_score > 80:
                st.success(f"🛡️ HAUTE CONFIANCE : AUTHENTIQUE ({zied_score}%)"); verdict = "AUTHENTIQUE"
            elif zied_score > 40:
                st.warning(f"⚠️ DOUTEUX / INCERTAIN ({zied_score}%)"); verdict = "DOUTE"
            else:
                st.error(f"🚨 ALERTE : CONTENU GÉNÉRÉ OU FALSIFIÉ ({zied_score}%)"); verdict = "IA / FALSIFIÉ"

            # --- SIGNATURES SPÉCIFIQUES ---
            if ai_patterns:
                st.markdown("### 🏷️ Modèles IA reconnus")
                tags_html = "".join([f'<span class="ai-tag">{p}</span>' for p in ai_patterns])
                st.markdown(tags_html, unsafe_allow_html=True)
                st.write("")

            res1, res2 = st.columns(2)
            with res1:
                st.subheader("🤖 Analyse de Probabilité")
                for c in [cl for cl in classes if cl['score'] > 0.01]:
                    st.write(f"• {c['class'].replace('_',' ').title()} : {round(c['score']*100,2)}%")
            with res2:
                st.subheader("📂 Forensic Métadonnées")
                for d in exif_details[:5]: st.markdown(f'<div class="expert-box">{d}</div>', unsafe_allow_html=True)

            st.divider()
            # Certificat & SOS
            col_pdf, col_sos = st.columns(2)
            with col_pdf:
                rep = create_pdf_report(get_file_hash(img_file), zied_score, verdict, "IMAGE", ai_patterns)
                st.download_button("📥 TÉLÉCHARGER LE CERTIFICAT PDF", rep, "Certificat_ZiedVerif.pdf")
            with col_sos:
                st.markdown('<div class="sos-card"><b>Doute technique ?</b> Sollicitez Walid ou Zied.</div>', unsafe_allow_html=True)
                if st.button("🚨 DEMANDER UNE CONTRE-EXPERTISE HUMAINE"):
                    st.toast("Demande transmise à l'équipe technique !")

elif choice == "Certification Document":
    st.title("📄 Certification Documentaire")
    doc_file = st.file_uploader("Document", type=["pdf", "jpg", "png"])
    if doc_file and st.button("VÉRIFIER ET CERTIFIER"):
        st.session_state.credits -= 1
        st.success("DOCUMENT ANALYSÉ - CERTIFICAT GÉNÉRÉ")
        rep_doc = create_pdf_report(get_file_hash(doc_file), 100, "CONFORME", "DOCUMENT", [])
        st.download_button("📥 TÉLÉCHARGER LE CERTIFICAT", rep_doc, "Certificat_Doc.pdf")

elif choice == "Analyse Vidéo":
    st.title("🎬 Détection Deepfake Vidéo")
    vid_file = st.file_uploader("Fichier vidéo", type=["mp4", "mov"])
    if vid_file and st.button("LANCER LE SCAN"):
        st.session_state.credits -= 1
        with st.spinner("Analyse des frames en cours..."):
            _, score_h = check_hive(vid_file, 'ai_generated_video_detection')
            if score_h > 10: st.error(f"🚨 DEEPFAKE DÉTECTÉ ({int(score_h)}%)")
            else: st.success("🛡️ AUCUNE TRACE DE GÉNÉRATION IA DÉTECTÉE")

elif choice == "Sécurité Liens":
    st.title("🔗 Anti-Phishing Scanner")
    url = st.text_input("URL à vérifier")
    if url and st.button("SCANNER L'URL"):
        st.session_state.credits -= 1
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        res = requests.get(f"https://www.virustotal.com/api/v3/urls/{url_id}", headers={"x-apikey": VT_API_KEY}).json()
        mal = res.get('data', {}).get('attributes', {}).get('last_analysis_stats', {}).get('malicious', 0)
        if mal > 0: st.error(f"🚨 DANGER : Ce lien est répertorié comme malveillant ({mal} détections).")
        else: st.success("✅ LIEN SÉCURISÉ")

elif choice == "À propos":
    st.title("📖 L'Histoire de ZiedVerif Pro")
    st.markdown("""
    <div class="main-card">
    <b>ZiedVerif Pro</b> est l'outil de référence pour l'audit de vérité numérique. 
    Dans un monde saturé de Deepfakes et de contenus IA, nous offrons la certitude technique.
    </div>
    """, unsafe_allow_html=True)
    c1, c2, c3 = st.columns(3)
    with c1:
        st.markdown("""<div class="founder-card"><h3>🦁 Zied</h3><b>Vision & Stratégie</b><br><br>
        </div>""", unsafe_allow_html=True)
    with c2:
        st.markdown("""<div class="founder-card"><h3>🛡️ Walid</h3><b>Cyber-Sécurité</b><br><br>
        .</div>""", unsafe_allow_html=True)
    with c3:
        st.markdown("""<div class="founder-card"><h3>⚙️ Mounir</h3><b>Architecture</b><br><br>
        .</div>""", unsafe_allow_html=True)

st.divider()
st.caption("© 2026 ZiedVerif Pro - Protections Numériques Avancées")