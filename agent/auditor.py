"""
auditor.py
==========
VC Auditor agent for performing due diligence on software repositories.

Author  : Staff Compiler Engineer / Technical VC Due Diligence Expert
Python  : 3.10+
Dependencies: requests, os, json, datetime
"""

import json
import os
import requests
import concurrent.futures
from datetime import datetime, timezone, time
from engine.graph_builder import DeepSemanticGraphBuilder


def _audit_single_file(filepath: str, code: str) -> str:

    """The 'Map' phase: Audits a single high-risk file."""

    api_key = os.getenv("GEMINI_API_KEY")

    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-3.0-flash:generateContent?key={api_key}"

    

    prompt = f"Audit this code for security/logic flaws. Be extremely concise. File: {filepath}\n\n{code[:5000]}"

    payload = {"contents": [{"parts": [{"text": prompt}]}]}

    

    try:

        res = requests.post(url, json=payload)

        return f"--- {filepath} ---\n" + res.json()['candidates'][0]['content']['parts'][0]['text']

    except Exception:

        return f"--- {filepath} ---\nAnalysis failed."

def mock_run_vc_audit(github_token, repo_name, owner, all_contents):
    print(f"[DEBUG] Starting MOCKED VC Audit for {owner}/{repo_name}...")

    # 1. Build Graph
    file_records = [{"filepath": fp, "code_string": code, "last_commit_date": "2024-01-01T00:00:00Z", "unique_author_count": 1} for fp, code in all_contents.items()]
    builder = DeepSemanticGraphBuilder()
    real_graph_payload = builder.build(file_records)

    # 2. Test the REAL Map Logic on a micro-subset (max 2 files)
    nodes = real_graph_payload.get("nodes", [])
    
    # LIMIT to top 2 files to save API costs during debugging
    test_nodes = sorted(nodes, key=lambda x: x.get("astComplexity", 0), reverse=True)[:2] 

    map_tasks = []
    for node in test_nodes:
        filepath = node["id"]
        if filepath in all_contents:
            map_tasks.append((filepath, all_contents[filepath]))

    print(f"[DEBUG] Testing REAL Map Phase on {len(map_tasks)} files...")
    local_summaries = []
    
    # Execute the actual _audit_single_file logic concurrently
    with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
        future_to_file = {executor.submit(_audit_single_file, fp, code): fp for fp, code in map_tasks}
        for future in concurrent.futures.as_completed(future_to_file):
            local_summaries.append(future.result())

    # 3. Return Mocked Reduce Report + Real Graph
    mock_llm_report = {
        "tech_stack_suitability": 8,
        "maintenance_risk": "Medium",
        "summary": "Mocked executive summary. The red flags below are from the REAL Gemini map-phase test.",
        "red_flags": local_summaries  # Displays the actual Gemini outputs for the 2 files tested
    }

    return {"llm_report": mock_llm_report, "graph_data": real_graph_payload}

'''
Sample gemini response for a codebase audit:
maintenance_risk	"Medium"
red_flags	
0	"Logic Error: 'startTime' is never initialized in background.js but is required by newtab.js for progress calculations, breaking the 'Stage' UI logic."
1	"Repo Identity Mismatch: The repository is named 'DailyDecisionSpinner', but 90% of the codebase is a productivity extension named 'LOCK IN'."
2	"Over-permissioning: Requesting '<all_urls>' host permissions for a simple whitelist blocker may lead to friction during Chrome Web Store review."
3	"Bypassability: The content script blocking method (overwriting innerHTML) is a 'nuclear' option that can be easily circumvented by tech-savvy users."
4	"The Decision Spinner component contains arbitrary/hardcoded logic for 'biases' that lacks actual statistical weighting or transparency."
summary	"The project demonstrates a competent implementation of Chrome Manifest V3 and modular JavaScript, though it suffers from a significant identity crisis between its repository name and core functionality. While the focus-timer extension logic is well-structured, the project lacks cohesive documentation and consistent data initialization."
tech_stack_suitability	8
'''
def run_vc_audit(github_token, repo_name, owner, all_contents):
    """
    Executes the full VC Audit using a Map-Reduce LLM Pipeline.
    """
    print(f"[DEBUG] Starting Real VC Audit for {owner}/{repo_name}...")

    # --- STEP 1: Build the Structural Graph ---
    file_records = [
        {
            "filepath": filepath,
            "code_string": code_string,
            "last_commit_date": "2024-01-01T00:00:00Z", 
            "unique_author_count": 1 
        }
        for filepath, code_string in all_contents.items()
    ]

    print(f"[DEBUG] Building semantic graph for {len(file_records)} files...")
    builder = DeepSemanticGraphBuilder()
    graph_payload = builder.build(file_records)

    # --- STEP 2: The MAP Phase (Concurrent Local Audits) ---
    nodes = graph_payload.get("nodes", [])
    high_risk_nodes = sorted(nodes, key=lambda x: x.get("astComplexity", 0), reverse=True)[:10]
    
    map_tasks = []
    for node in high_risk_nodes:
        filepath = node["id"]
        if filepath in all_contents:
            map_tasks.append((filepath, all_contents[filepath]))

    print(f"[DEBUG] Mapping {len(map_tasks)} high-risk files to Gemini concurrently...")
    local_summaries = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        future_to_file = {executor.submit(_audit_single_file, fp, code): fp for fp, code in map_tasks}
        for future in concurrent.futures.as_completed(future_to_file):
            local_summaries.append(future.result())

    combined_local_findings = "\n\n".join(local_summaries)

    # --- STEP 3: The REDUCE Phase (Executive Report) ---
    print("[DEBUG] Reducing local findings into final VC Report...")
    api_key = os.getenv("GOOGLE_API_KEY")
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-3.1-pro-preview-customtools:generateContent?key={api_key}"

    prompt = f"""
    You are a Staff Compiler Engineer and Technical VC Due Diligence Expert. Your task is to perform a deep-dive audit.

    Repository Name: {repo_name} (Owner: {owner})

    [GLOBAL GRAPH ARCHITECTURE (Top 50 links)]
    {json.dumps(graph_payload.get('links', [])[:50])}
    
    [LOCAL FILE FINDINGS (From Map Phase)]
    {combined_local_findings}
    
    Your task is to provide a rigorous technical assessment based on the graph and the specific local findings.
    Provide a JSON response with exactly these fields:
    {{
      "velocity_score": (Int 1-100),
      "tech_debt_risk": (String "High", "Medium", or "Low"),
      "maintenance_risk": (String "High", "Medium", or "Low"),
      "executive_summary": (String) A 2-sentence executive summary.,
      "positive_aspects": (List of strings) Strengths of the architecture.,
      "critical_flaws": (List of strings) Security or architectural concerns.
    }}
    """

    payload = {
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"response_mime_type": "application/json"}
    }

    print("[DEBUG] Sending Reduce payload to Gemini...")
    ai_response = requests.post(url, json=payload)
    
    if ai_response.status_code !=200:
        print("[ERROR] Gemini Token/Quota Exceeded (HTTP 429).")
        return {
            "error_type": "TOKEN_LIMIT_EXCEEDED",
            "report": {
                "velocity_score": 0,
                "tech_debt_risk": "Unknown",
                "maintenance_risk": "Unknown",
                "executive_summary": "Incomplete Audit: The codebase size exceeded the LLM context window or API quota.",
                "positive_aspects": [],
                "critical_flaws": ["System Warning: LLM resource exhausted. Structural graph rendered, but AI analysis was aborted."]
            },
            "graph_data": graph_payload # Still return the graph so the UI doesn't break!
        }

    llm_report = {}
    if ai_response.status_code == 200:
        try:
            raw_text = ai_response.json()['candidates'][0]['content']['parts'][0]['text']
            llm_report = json.loads(raw_text)
        except Exception as e:
            print(f"[ERROR] Failed to parse JSON: {e}")
            llm_report = {"error": "Parse failed", "summary": "Failed to parse AI output.", "red_flags": []}
    else:
        print(f"[ERROR] Gemini Audit Failed: {ai_response.text}")
        llm_report = {
            "error": "AI Audit failed",
            "summary": "Could not generate AI report.",
            "red_flags": [f"API Error: {ai_response.status_code}"]
        }

    # --- STEP 4: RETURN COMBINED PAYLOAD ---
    return {
        "llm_report": llm_report,
        "graph_data": graph_payload
    }
