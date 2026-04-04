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
from datetime import datetime, timezone

from engine.graph_builder import DeepSemanticGraphBuilder

def mock_run_vc_audit(github_token, repo_name, owner, all_contents):
    """
    MOCKED VC Auditor for Local Development.
    1. Fetches code/commits using the Vault Token.
    2. Builds the REAL Deep Semantic Graph.
    3. Mocks the LLM response to save API calls and time.
    4. Returns the combined Report + Graph.
    """

    print(f"[DEBUG] Starting MOCKED VC Audit for {owner}/{repo_name}...")

    # ==========================================
    # 1. Mock Graph Data for Debugging (Flask App Structure)
    # ==========================================
    print("[DEBUG] Using MOCK graph data for debugging links.")
    
    # Try to load from graph_dump.json, fallback to hardcoded mock
    mock_graph_payload = {}
    try:
        # Try loading from current directory first
        with open("graph_dump.json", "r") as f:
            mock_graph_payload = json.load(f)
            print("[DEBUG] Loaded graph from graph_dump.json", mock_graph_payload)
    except FileNotFoundError:
        try:
            # Try loading from auth0-flask-app
            import sys
            from pathlib import Path
            auth0_path = Path(__file__).parent.parent.parent / "auth0-flask-app" / "graph_dump.json"
            with open(auth0_path, "r") as f:
                mock_graph_payload = json.load(f)
                print(f"[DEBUG] Loaded graph from {auth0_path}")
        except (FileNotFoundError, Exception) as e:
            print(f"[DEBUG] Could not load graph_dump.json ({e}), using hardcoded mock graph")
            # Fallback to hardcoded mock graph
            mock_graph_payload = {
                "nodes": [
                    {"id": "app/__init__.py", "name": "__init__.py", "group": "asset", "val": 8},
                    {"id": "app/routes/auth.py", "name": "auth.py", "group": "neutral", "val": 10},
                    {"id": "app/routes/github.py", "name": "github.py", "group": "risk", "val": 12},
                    {"id": "app/routes/audit.py", "name": "audit.py", "group": "neutral", "val": 6},
                    {"id": "app/services/auth0_client.py", "name": "auth0_client.py", "group": "liability", "val": 15},
                    {"id": "app/services/github_client.py", "name": "github_client.py", "group": "risk", "val": 14},
                    {"id": "app/templates/base.html", "name": "base.html", "group": "neutral", "val": 5},
                    {"id": "app/templates/profile.html", "name": "profile.html", "group": "neutral", "val": 7},
                    {"id": "app/static/js/main.js", "name": "main.js", "group": "asset", "val": 9},
                    {"id": "app/static/js/graph3d.js", "name": "graph3d.js", "group": "asset", "val": 11},
                    {"id": "agent/auditor.py", "name": "auditor.py", "group": "risk", "val": 13},
                    {"id": "engine/graph_builder.py", "name": "graph_builder.py", "group": "asset", "val": 10}
                ],
                "links": [
                    {"source": "app/__init__.py", "target": "app/routes/auth.py"},
                    {"source": "app/__init__.py", "target": "app/routes/github.py"},
                    {"source": "app/__init__.py", "target": "app/routes/audit.py"},
                    {"source": "app/__init__.py", "target": "app/services/auth0_client.py"},
                    {"source": "app/__init__.py", "target": "app/services/github_client.py"},
                    {"source": "app/routes/auth.py", "target": "app/services/auth0_client.py"},
                    {"source": "app/routes/github.py", "target": "app/services/github_client.py"},
                    {"source": "app/routes/audit.py", "target": "agent/auditor.py"},
                    {"source": "agent/auditor.py", "target": "engine/graph_builder.py"},
                    {"source": "app/static/js/main.js", "target": "app/static/js/graph3d.js"},
                    {"source": "app/templates/profile.html", "target": "app/templates/base.html"},
                    {"source": "app/routes/github.py", "target": "app/static/js/main.js"}
                ]
            }
    
    graph_payload = mock_graph_payload

    # ==========================================
    # 2. Fetch Contextual GitHub Data (REAL)
    # ==========================================
    headers = {
        "Authorization": f"token {github_token}",
        "Accept": "application/vnd.github.v3+json"
    }

    # Fetch recent commits
    commits_res = requests.get(f"https://api.github.com/repos/{owner}/{repo_name}/commits?per_page=10", headers=headers)
    commit_messages = []
    if commits_res.status_code == 200:
        commits = commits_res.json()
        commit_messages = [c['commit']['message'] for c in commits if 'commit' in c]

    # Fetch tech stack (languages)
    langs_res = requests.get(f"https://api.github.com/repos/{owner}/{repo_name}/languages", headers=headers)
    tech_stack = {}
    if langs_res.status_code == 200:
        tech_stack = langs_res.json()

    # ==========================================
    # 3. MOCK the LLM Response
    # ==========================================
    print("[DEBUG] Bypassing Gemini API. Generating MOCK report...")

    # Create a realistic-looking mock report that matches your expected schema
    mock_parsed_report = {
      "velocity_score": 85,
      "tech_debt_risk": "Medium",
      "maintenance_risk": "Medium",
      "executive_summary": f"The '{repo_name}' repository demonstrates a competent initial architecture with clear separation of concerns, typical of early-stage startups. However, there is a pronounced reliance on a few central modules ('God Objects') and an absence of API authentication on several critical routes, introducing significant operational and security risks that must be addressed before scaling.",
      "positive_aspects": [
        "Consistent use of the declared tech stack across the codebase.",
        "Clear module boundaries in the primary business logic.",
        "Recent commit velocity indicates an active and engaged development cycle."
      ],
      "critical_flaws": [
        "Unprotected API Endpoints: Several routes handling sensitive state mutations lack explicit authorization checks.",
        "High Entropy Secrets: Hardcoded credentials or API keys were detected in the configuration layer."
      ],
      "red_flags": [
        "Security Gap: PII (Personally Identifiable Information) flows through modules with 0% test coverage.",
        "Architecture Risk: Central database handler has a massive in-degree, creating a severe chokepoint and Bus Factor risk.",
        "Logic Error: Silent exception swallowing detected in data ingestion pipeline."
      ],
      "tech_stack_suitability": 7
    }

    # ==========================================
    # 4. Return the combined Payload
    # ==========================================
    print("[DEBUG] Successfully generated MOCK VC Report.")

    return {
        "llm_report": mock_parsed_report,
        "graph_data": graph_payload
    }

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
    The AI Auditor logic.
    1. Builds the Semantic Dependency Graph.
    2. Performs the Gemini 3 Flash analysis on the codebase.
    3. Returns the combined payload for the 3D Dashboard.
    """
    
    # --- STEP 1: GENERATE SEMANTIC GRAPH ---
    print(f"[DEBUG] Building semantic graph for {repo_name}...")
    try:
        builder = DeepSemanticGraphBuilder()

        # Transform dict {path: code} -> list of FileRecords
        formatted_records = []
        for path, content in all_contents.items():
            formatted_records.append({
                "filepath": path,
                "code_string": content,
                "last_commit_date": "2026-04-04T00:00:00Z", # Placeholder or fetch real date
                "unique_author_count": 1                     # Placeholder
            })
        # Ensure all_contents is passed to your builder to generate the nodes/links
        graph_payload = builder.build(formatted_records) 
    except Exception as e:
        print(f"[ERROR] Graph Builder failed: {e}")
        # Fallback to empty graph if builder fails to prevent 500
        graph_payload = {"nodes": [], "links": []}

    # --- STEP 2: PERFORM AI ANALYSIS ---
    api_key = os.getenv("GOOGLE_API_KEY")
    url = f"https://generativelanguage.googleapis.com/v1beta/models/gemini-flash-latest:generateContent?key={api_key}"

    # Build the "Audit Scroll"
    codebase_summary = ""
    for path, content in all_contents.items():
        codebase_summary += f"\n--- FILE: {path} ---\n{content}\n"

    payload = {
        "contents": [{
            "parts": [{
                "text": f"""
                You are a Technical VC Auditor performing due diligence on a startup.
                Analyze the following repository: {repo_name} (Owner: {owner})
                
                FULL CODEBASE CONTENT:
                {codebase_summary}
                
                Your task is to provide a rigorous technical assessment.
                Provide a JSON response with exactly these fields:
                1. "tech_stack_suitability": (Int 1-10)
                2. "maintenance_risk": (String "High", "Medium", or "Low")
                3. "summary": (String) A 2-sentence executive summary for an investor.
                4. "red_flags": (List of strings) Any security or architectural concerns found.
                """
            }]
        }],
        "generationConfig": {
            "response_mime_type": "application/json"
        }
    }

    print(f"[DEBUG] Sending {len(codebase_summary)} chars to Gemini...")
    ai_response = requests.post(url, json=payload)
    
    llm_report = {}
    if ai_response.status_code == 200:
        raw_text = ai_response.json()['candidates'][0]['content']['parts'][0]['text']
        llm_report = json.loads(raw_text)
    else:
        print(f"[ERROR] Gemini Audit Failed: {ai_response.text}")
        llm_report = {
            "error": "AI Audit failed",
            "summary": "Could not generate AI report.",
            "red_flags": ["API Error: Gemini model was unreachable."]
        }

    # --- STEP 3: RETURN COMBINED PAYLOAD ---
    # This structure matches what main.js is looking for
    return {
        "llm_report": llm_report,
        "graph_data": graph_payload
    }