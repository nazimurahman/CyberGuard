from src.ui import create_ui_app
from src.agents.agent_orchestrator import AgentOrchestrator
from src.web_security.scanner import WebSecurityScanner

# Initialize system components
orchestrator = AgentOrchestrator()
scanner = WebSecurityScanner(config)

# Create UI app
app = create_ui_app(
    agent_orchestrator=orchestrator,
    security_scanner=scanner,
    config={
        'SECRET_KEY': 'your-secret-key',
        'DEBUG': False
    }
)

# Run the app
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=8080, debug=True)
    
    


import requests

# Scan a website
response = requests.post(
    'http://localhost:8080/api/v1/scan',
    headers={
        'X-API-Key': 'cyberguard-dev-2024',
        'Content-Type': 'application/json'
    },
    json={
        'url': 'https://example.com',
        'options': {'depth': 2}
    }
)

# Get scan results
scan_id = response.json()['data']['scan_id']
results = requests.get(
    f'http://localhost:8080/api/v1/scan/{scan_id}',
    headers={'X-API-Key': 'cyberguard-dev-2024'}
)