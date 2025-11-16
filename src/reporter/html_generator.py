import os
from datetime import datetime
from jinja2 import Template
from src.models.scan_result import ScanResult

class HTMLGenerator:
    def __init__(self, scan_result: ScanResult):
        self.scan_result = scan_result
        
    def generate(self, output_path: str = "report.html") -> str:
        template_str = self._get_template()
        template = Template(template_str)
        
        findings_by_file = {}
        for finding in self.scan_result.findings:
            if finding.file_path not in findings_by_file:
                findings_by_file[finding.file_path] = []
            findings_by_file[finding.file_path].append(finding)
        
        findings_dict_list = [f.to_dict() for f in self.scan_result.findings]
        
        html_content = template.render(
            scan_result=self.scan_result,
            findings_by_file=findings_by_file,
            findings_dict_list=findings_dict_list,
            timestamp=datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            risk_score=self.scan_result.get_risk_score(),
            severity_counts=self.scan_result.get_findings_by_severity(),
            detector_counts=self.scan_result.get_findings_by_detector()
        )
        
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(html_content)
            
        return output_path
        
    def _get_template(self) -> str:
        return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IsItBackdoored - Scan Report</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: #0d1117;
            color: #c9d1d9;
            line-height: 1.6;
        }
        .header {
            background: linear-gradient(135deg, #0d7377 0%, #14a085 100%);
            padding: 30px;
            text-align: center;
            box-shadow: 0 4px 6px rgba(0,0,0,0.3);
        }
        .header h1 { color: white; font-size: 36px; margin-bottom: 10px; }
        .header p { color: rgba(255,255,255,0.9); font-size: 14px; }
        .container { max-width: 1400px; margin: 0 auto; padding: 20px; }
        .summary {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        .card {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.2);
        }
        .card h3 { color: #8b949e; font-size: 14px; margin-bottom: 10px; text-transform: uppercase; }
        .card .value { font-size: 32px; font-weight: bold; }
        .risk-critical { color: #ff4444; }
        .risk-high { color: #ff6b6b; }
        .risk-medium { color: #ffa500; }
        .risk-low { color: #4caf50; }
        .main-content { display: grid; grid-template-columns: 300px 1fr; gap: 20px; }
        .file-tree {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 20px;
            max-height: 800px;
            overflow-y: auto;
        }
        .file-tree h2 { margin-bottom: 15px; color: #58a6ff; }
        .file-item {
            padding: 8px;
            margin: 4px 0;
            border-radius: 4px;
            cursor: pointer;
            transition: background 0.2s;
            font-size: 13px;
        }
        .file-item:hover { background: #21262d; }
        .file-item.has-findings { color: #ff6b6b; }
        .findings-list { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; }
        .findings-list h2 { margin-bottom: 15px; color: #58a6ff; }
        .finding {
            background: #0d1117;
            border-left: 4px solid;
            padding: 15px;
            margin-bottom: 15px;
            border-radius: 4px;
            cursor: pointer;
            transition: transform 0.2s;
        }
        .finding:hover { transform: translateX(5px); }
        .finding.CRITICAL { border-color: #ff4444; }
        .finding.HIGH { border-color: #ff6b6b; }
        .finding.MEDIUM { border-color: #ffa500; }
        .finding.LOW { border-color: #ffff00; }
        .finding-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 10px; }
        .finding-title { font-weight: bold; font-size: 16px; }
        .severity-badge {
            padding: 4px 12px;
            border-radius: 12px;
            font-size: 11px;
            font-weight: bold;
            text-transform: uppercase;
        }
        .severity-CRITICAL { background: #ff4444; color: white; }
        .severity-HIGH { background: #ff6b6b; color: white; }
        .severity-MEDIUM { background: #ffa500; color: white; }
        .severity-LOW { background: #ffff00; color: black; }
        .finding-meta { font-size: 13px; color: #8b949e; margin-bottom: 8px; }
        .finding-desc { color: #c9d1d9; margin-bottom: 10px; }
        .modal {
            display: none;
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0,0,0,0.8);
            z-index: 1000;
            overflow-y: auto;
        }
        .modal-content {
            background: #161b22;
            max-width: 900px;
            margin: 50px auto;
            border-radius: 8px;
            border: 1px solid #30363d;
        }
        .modal-header {
            padding: 20px;
            border-bottom: 1px solid #30363d;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .modal-body { padding: 20px; }
        .close-btn {
            background: none;
            border: none;
            color: #8b949e;
            font-size: 28px;
            cursor: pointer;
            padding: 0;
            width: 30px;
            height: 30px;
        }
        .close-btn:hover { color: #c9d1d9; }
        .code-snippet {
            background: #0d1117;
            border: 1px solid #30363d;
            border-radius: 4px;
            padding: 15px;
            font-family: 'Consolas', 'Courier New', monospace;
            font-size: 13px;
            overflow-x: auto;
            white-space: pre;
            margin: 15px 0;
        }
        .recommendation {
            background: #1c2128;
            border-left: 4px solid #0d7377;
            padding: 15px;
            margin-top: 15px;
            border-radius: 4px;
        }
        .charts { display: grid; grid-template-columns: 1fr 1fr; gap: 20px; margin-top: 30px; }
        .chart-card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; }
        .chart-card h3 { margin-bottom: 15px; color: #58a6ff; }
        .bar { background: #0d7377; height: 30px; margin: 10px 0; border-radius: 4px; position: relative; }
        .bar-label { position: absolute; left: 10px; top: 50%; transform: translateY(-50%); color: white; font-weight: bold; }
        ::-webkit-scrollbar { width: 10px; }
        ::-webkit-scrollbar-track { background: #0d1117; }
        ::-webkit-scrollbar-thumb { background: #30363d; border-radius: 5px; }
        ::-webkit-scrollbar-thumb:hover { background: #484f58; }
    </style>
</head>
<body>
    <div class="header">
        <h1>🔍 IsItBackdoored</h1>
        <p>Security Scan Report - {{ timestamp }}</p>
    </div>
    
    <div class="container">
        <div class="summary">
            <div class="card">
                <h3>Risk Score</h3>
                <div class="value {% if risk_score >= 75 %}risk-critical{% elif risk_score >= 50 %}risk-high{% elif risk_score >= 25 %}risk-medium{% else %}risk-low{% endif %}">
                    {{ risk_score }}/100
                </div>
            </div>
            <div class="card">
                <h3>Total Files</h3>
                <div class="value" style="color: #58a6ff;">{{ scan_result.scanned_files }}</div>
            </div>
            <div class="card">
                <h3>Total Findings</h3>
                <div class="value" style="color: #ff6b6b;">{{ scan_result.findings|length }}</div>
            </div>
            <div class="card">
                <h3>Critical Issues</h3>
                <div class="value risk-critical">{{ severity_counts.CRITICAL }}</div>
            </div>
        </div>
        
        <div class="main-content">
            <div class="file-tree">
                <h2>📁 Files</h2>
                {% for file_path, findings in findings_by_file.items() %}
                <div class="file-item has-findings" onclick="filterByFile('{{ file_path }}')">
                    ⚠️ {{ file_path }} ({{ findings|length }})
                </div>
                {% endfor %}
            </div>
            
            <div class="findings-list">
                <h2>🚨 Findings</h2>
                <div id="findings-container">
                    {% for finding in scan_result.findings %}
                    <div class="finding {{ finding.severity }}" onclick="showModal({{ loop.index0 }})">
                        <div class="finding-header">
                            <div class="finding-title">{{ finding.title }}</div>
                            <span class="severity-badge severity-{{ finding.severity }}">{{ finding.severity }}</span>
                        </div>
                        <div class="finding-meta">
                            📄 {{ finding.file_path }}:{{ finding.line_number }} | 
                            🎯 Confidence: {{ finding.confidence }}% | 
                            🔍 {{ finding.detector }}
                        </div>
                        <div class="finding-desc">{{ finding.description }}</div>
                    </div>
                    {% endfor %}
                </div>
            </div>
        </div>
        
        <div class="charts">
            <div class="chart-card">
                <h3>Findings by Severity</h3>
                {% for severity, count in severity_counts.items() %}
                {% if count > 0 %}
                <div class="bar" style="width: {{ (count / scan_result.findings|length * 100)|int }}%;">
                    <span class="bar-label">{{ severity }}: {{ count }}</span>
                </div>
                {% endif %}
                {% endfor %}
            </div>
            
            <div class="chart-card">
                <h3>Findings by Detector</h3>
                {% for detector, count in detector_counts.items() %}
                <div class="bar" style="width: {{ (count / scan_result.findings|length * 100)|int }}%;">
                    <span class="bar-label">{{ detector }}: {{ count }}</span>
                </div>
                {% endfor %}
            </div>
        </div>
    </div>
    
    <div id="modal" class="modal" onclick="closeModal(event)">
        <div class="modal-content" onclick="event.stopPropagation()">
            <div class="modal-header">
                <h2 id="modal-title"></h2>
                <button class="close-btn" onclick="closeModal()">&times;</button>
            </div>
            <div class="modal-body">
                <div id="modal-meta"></div>
                <div id="modal-desc"></div>
                <div class="code-snippet" id="modal-code"></div>
                <div class="recommendation">
                    <strong>💡 Recommendation:</strong>
                    <p id="modal-recommendation"></p>
                </div>
            </div>
        </div>
    </div>
    
    <script>
        const findings = {{ findings_dict_list | tojson }};
        
        function showModal(index) {
            const finding = findings[index];
            document.getElementById('modal-title').textContent = finding.title;
            document.getElementById('modal-meta').innerHTML = `
                <p><strong>File:</strong> ${finding.file_path}:${finding.line_number}</p>
                <p><strong>Severity:</strong> <span class="severity-badge severity-${finding.severity}">${finding.severity}</span></p>
                <p><strong>Confidence:</strong> ${finding.confidence}%</p>
                <p><strong>Detector:</strong> ${finding.detector}</p>
            `;
            document.getElementById('modal-desc').innerHTML = `<p style="margin: 15px 0;"><strong>Description:</strong> ${finding.description}</p>`;
            document.getElementById('modal-code').textContent = finding.code_snippet;
            document.getElementById('modal-recommendation').textContent = finding.recommendation;
            document.getElementById('modal').style.display = 'block';
        }
        
        function closeModal(event) {
            if (!event || event.target.id === 'modal') {
                document.getElementById('modal').style.display = 'none';
            }
        }
        
        function filterByFile(filePath) {
            const findingsContainer = document.getElementById('findings-container');
            const allFindings = findingsContainer.querySelectorAll('.finding');
            allFindings.forEach((el, idx) => {
                if (findings[idx].file_path === filePath) {
                    el.style.display = 'block';
                } else {
                    el.style.display = 'none';
                }
            });
        }
    </script>
</body>
</html>'''
