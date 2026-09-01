import streamlit as st
import google.generativeai 
import json
from sources import detect_ioc_type, is_valid_ioc, SOURCES

st.set_page_config(page_title="ThreatLens", page_icon="🛡️", layout="wide")

st.title("🛡️ ThreatLens")
st.markdown("Check if an IP address, Domain, or URL is safe using VirusTotal, WHOIS, and Gemini AI analysis.")

# Sidebar setup for keys & levels
st.sidebar.header("Configuration")
vt_api_key = st.sidebar.text_input("VirusTotal API Key", type="password")
gemini_api_key = st.sidebar.text_input("Gemini API Key", type="password")
knowledge_level = st.sidebar.select_slider(
    "Target Audience Level",
    options=["Beginner", "Intermediate", "Expert"],
    value="Intermediate"
)

# Input selection option for user
input_mode = st.radio("Select Input Type:", ["Direct URL / Address Input", "Paste Raw Target"], horizontal=True)

if input_mode == "Direct URL / Address Input":
    ioc_input = st.text_input("Enter Web URL (e.g., https://example.com/login or http://malicious-site.org):")
else:
    ioc_input = st.text_input("Enter IP, Domain, or URL:", placeholder="e.g., 8.8.8.8, example.com, or https://test.com")

if st.button("Analyze Threat", type="primary"):
    if not ioc_input:
        st.warning("Please enter a target URL or address to analyze.")
    elif not is_valid_ioc(ioc_input):
        st.error("Invalid input format. Please provide a valid URL, IP address, or Domain name.")
    else:
        ioc_type = detect_ioc_type(ioc_input)
        st.info(f"Target Identified As: **{ioc_type.upper()}**")

        results = []

        # Collect data from sources
        with st.spinner("Querying threat intelligence sources..."):
            if "WHOIS" in SOURCES:
                results.append(SOURCES["WHOIS"](ioc_input))
            if "VirusTotal" in SOURCES:
                if vt_api_key:
                    results.append(SOURCES["VirusTotal"](ioc_input, vt_api_key))
                else:
                    st.warning("VirusTotal API key is missing; skipping VirusTotal scan.")

        # Display raw source findings
        st.subheader("Source Findings")
        cols = st.columns(len(results) if results else 1)
        for idx, res in enumerate(results):
            with cols[idx]:
                st.metric(
                    label=res["source"],
                    value=res["verdict"],
                    delta=f"Risk Score: {res['risk_score']}%",
                    delta_color="inverse"
                )
                with st.expander(f"Raw Data - {res['source']}"):
                    st.json(res["raw_data"])

        # Gemini AI Analysis using gemini-3.6-flash
        if gemini_api_key:
            with st.spinner(f"Generating {knowledge_level}-level AI Security Summary..."):
                try:
                    genai.configure(api_key=gemini_api_key)
                    model = genai.GenerativeModel("gemini-3.6-flash")

                    prompt = f"""
                    You are a cybersecurity expert. Analyze the following scan results for the target '{ioc_input}' ({ioc_type}).
                    Tailor your explanation for a **{knowledge_level}** level user.

                    Source Data:
                    {json.dumps(results, default=str)}

                    Return ONLY a JSON response matching this schema:
                    {{
                        "verdict": "Clean / Suspicious / Malicious",
                        "risk_score": 0-100,
                        "summary": "Brief explanation tailored to the knowledge level",
                        "key_findings": ["Finding 1", "Finding 2"],
                        "recommendation": "Actionable advice"
                    }}
                    """

                    response = model.generate_content(prompt)
                    
                    # Clean markdown wrapping if present before parsing JSON
                    raw_text = response.text.strip()
                    if raw_text.startswith("```json"):
                        raw_text = raw_text[7:]
                    if raw_text.endswith("```"):
                        raw_text = raw_text[:-3]
                    
                    ai_data = json.loads(raw_text.strip())

                    st.markdown("---")
                    st.subheader("🤖 AI Security Insights")
                    
                    verdict = ai_data.get("verdict", "Clean")
                    verdict_color = (
                        "green" if verdict == "Clean"
                        else ("orange" if verdict == "Suspicious" else "red")
                    )
                    st.markdown(f"### Overall Verdict: :{verdict_color}[{verdict}] (Risk Score: {ai_data.get('risk_score', 0)}/100)")
                    st.write(ai_data.get("summary"))

                    st.markdown("#### Key Findings")
                    for finding in ai_data.get("key_findings", []):
                        st.markdown(f"- {finding}")

                    st.info(f"**Recommendation:** {ai_data.get('recommendation')}")

                except Exception as e:
                    st.error(f"Failed to generate AI insights: {str(e)}")
        else:
            st.warning("Provide a Gemini API key in the sidebar to enable AI analysis.")
