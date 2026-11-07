"""Control framework reference data.

Kept deliberately compact: enough of each framework to map a control or a risk
to a citation an auditor recognises, not a full copy of any standard.
"""

FRAMEWORKS = {
    "NIST_CSF_2": {
        "name": "NIST Cybersecurity Framework 2.0",
        "short": "NIST CSF 2.0",
        "items": [
            ("GV.OC", "Organizational Context"), ("GV.RM", "Risk Management Strategy"), ("GV.RR", "Roles, Responsibilities, and Authorities"),
            ("GV.PO", "Policy"), ("GV.OV", "Oversight"), ("GV.SC", "Cybersecurity Supply Chain Risk Management"),
            ("GV.SC-04", "Suppliers are known and prioritized by criticality"), ("GV.SC-07", "Supplier risks are understood, recorded, prioritized, assessed, responded to, and monitored"),
            ("ID.AM", "Asset Management"), ("ID.AM-01", "Inventories of hardware managed by the organization are maintained"),
            ("ID.RA", "Risk Assessment"), ("ID.RA-01", "Vulnerabilities in assets are identified, validated, and recorded"),
            ("ID.RA-05", "Threats, vulnerabilities, likelihoods, and impacts are used to understand inherent risk and inform response prioritization"),
            ("ID.IM", "Improvement"),
            ("PR.AA", "Identity Management, Authentication, and Access Control"), ("PR.AA-03", "Users, services, and hardware are authenticated"),
            ("PR.AA-05", "Access permissions, entitlements, and authorizations are defined in a policy, managed, enforced, and reviewed"),
            ("PR.AT", "Awareness and Training"), ("PR.AT-01", "Personnel are provided with awareness and training"),
            ("PR.DS", "Data Security"), ("PR.DS-01", "The confidentiality, integrity, and availability of data-at-rest are protected"),
            ("PR.DS-02", "The confidentiality, integrity, and availability of data-in-transit are protected"),
            ("PR.PS", "Platform Security"), ("PR.PS-01", "Configuration management practices are established and applied"),
            ("PR.PS-02", "Software is maintained, replaced, and removed commensurate with risk"), ("PR.PS-06", "Secure software development practices are integrated"),
            ("PR.IR", "Technology Infrastructure Resilience"), ("PR.IR-01", "Networks and environments are protected from unauthorized logical access and usage"),
            ("PR.IR-04", "Adequate resource capacity to ensure availability is maintained"),
            ("DE.CM", "Continuous Monitoring"), ("DE.CM-01", "Networks and network services are monitored to find potentially adverse events"),
            ("DE.CM-09", "Computing hardware and software, runtime environments, and their data are monitored"),
            ("DE.AE", "Adverse Event Analysis"),
            ("RS.MA", "Incident Management"), ("RS.MA-01", "The incident response plan is executed in coordination with relevant third parties"),
            ("RS.AN", "Incident Analysis"), ("RS.CO", "Incident Response Reporting and Communication"), ("RS.MI", "Incident Mitigation"),
            ("RC.RP", "Incident Recovery Plan Execution"), ("RC.RP-01", "The recovery portion of the incident response plan is executed"),
            ("RC.CO", "Incident Recovery Communication"),
        ],
    },
    "ISO_27001_2022": {
        "name": "ISO/IEC 27001:2022 Annex A",
        "short": "ISO 27001:2022",
        "items": [
            ("A.5.1", "Policies for information security"), ("A.5.7", "Threat intelligence"), ("A.5.9", "Inventory of information and other associated assets"),
            ("A.5.10", "Acceptable use of information and other associated assets"), ("A.5.12", "Classification of information"),
            ("A.5.15", "Access control"), ("A.5.17", "Authentication information"), ("A.5.18", "Access rights"),
            ("A.5.19", "Information security in supplier relationships"), ("A.5.20", "Addressing information security within supplier agreements"),
            ("A.5.21", "Managing information security in the ICT supply chain"), ("A.5.23", "Information security for use of cloud services"),
            ("A.5.24", "Information security incident management planning and preparation"), ("A.5.26", "Response to information security incidents"),
            ("A.5.29", "Information security during disruption"), ("A.5.30", "ICT readiness for business continuity"),
            ("A.5.34", "Privacy and protection of PII"), ("A.5.35", "Independent review of information security"),
            ("A.6.3", "Information security awareness, education and training"), ("A.6.8", "Information security event reporting"),
            ("A.7.1", "Physical security perimeters"), ("A.7.10", "Storage media"),
            ("A.8.1", "User endpoint devices"), ("A.8.2", "Privileged access rights"), ("A.8.3", "Information access restriction"),
            ("A.8.5", "Secure authentication"), ("A.8.6", "Capacity management"), ("A.8.7", "Protection against malware"),
            ("A.8.8", "Management of technical vulnerabilities"), ("A.8.9", "Configuration management"), ("A.8.10", "Information deletion"),
            ("A.8.12", "Data leakage prevention"), ("A.8.13", "Information backup"), ("A.8.15", "Logging"), ("A.8.16", "Monitoring activities"),
            ("A.8.20", "Networks security"), ("A.8.24", "Use of cryptography"), ("A.8.25", "Secure development life cycle"),
            ("A.8.28", "Secure coding"), ("A.8.29", "Security testing in development and acceptance"), ("A.8.32", "Change management"),
        ],
    },
    "SOC2_TSC": {
        "name": "AICPA SOC 2 Trust Services Criteria",
        "short": "SOC 2",
        "items": [
            ("CC1.1", "Commitment to integrity and ethical values"), ("CC2.2", "Internal communication of objectives and responsibilities"),
            ("CC3.2", "Identification and analysis of risk"), ("CC4.1", "Ongoing and separate evaluations of controls"),
            ("CC6.1", "Logical access security software, infrastructure, and architectures"), ("CC6.2", "Registration and authorization of new users"),
            ("CC6.3", "Removal and review of access"), ("CC6.6", "Security measures against threats from outside system boundaries"),
            ("CC6.7", "Restriction of transmission, movement, and removal of information"), ("CC6.8", "Prevention and detection of unauthorized software"),
            ("CC7.1", "Detection of configuration changes and vulnerabilities"), ("CC7.2", "Monitoring for anomalies and security events"),
            ("CC7.3", "Evaluation of security events"), ("CC7.4", "Incident response program"), ("CC7.5", "Recovery from incidents"),
            ("CC8.1", "Change management"), ("CC9.1", "Risk mitigation activities"), ("CC9.2", "Vendor and business partner risk management"),
            ("A1.2", "Environmental protections, backup, and recovery infrastructure"), ("A1.3", "Recovery plan testing"),
            ("C1.1", "Identification and protection of confidential information"), ("P3.1", "Personal information collection consistent with objectives"),
        ],
    },
    "NIST_AI_RMF": {
        "name": "NIST AI Risk Management Framework 1.0",
        "short": "NIST AI RMF",
        "items": [
            ("GOVERN 1.1", "Legal and regulatory requirements involving AI are understood, managed, and documented"),
            ("GOVERN 1.2", "Characteristics of trustworthy AI are integrated into organizational policies and practices"),
            ("GOVERN 4.1", "Policies foster a critical thinking and safety-first mindset in AI design and deployment"),
            ("GOVERN 6.1", "Policies address AI risks associated with third-party software, data, and supply chain"),
            ("MAP 1.1", "Intended purposes, beneficial uses, context-specific laws, norms, and expectations are documented"),
            ("MAP 5.1", "Likelihood and magnitude of each identified impact are identified and documented"),
            ("MEASURE 2.6", "The AI system is evaluated regularly for safety risks"),
            ("MEASURE 2.7", "AI system security and resilience are evaluated and documented"),
            ("MEASURE 2.8", "Risks associated with transparency and accountability are examined and documented"),
            ("MEASURE 2.10", "Privacy risk of the AI system is examined and documented"),
            ("MANAGE 1.3", "Responses to high-priority AI risks are developed, planned, and documented"),
            ("MANAGE 2.4", "Mechanisms exist to supersede, disengage, or deactivate AI systems that behave inconsistently with intended use"),
            ("MANAGE 3.1", "AI risks and benefits from third-party resources are regularly monitored and controlled"),
            ("MANAGE 4.1", "Post-deployment AI system monitoring plans are implemented"),
        ],
    },
    "OWASP_LLM_2025": {
        "name": "OWASP Top 10 for LLM Applications 2025",
        "short": "OWASP LLM Top 10",
        "items": [
            ("LLM01", "Prompt Injection"), ("LLM02", "Sensitive Information Disclosure"), ("LLM03", "Supply Chain"),
            ("LLM04", "Data and Model Poisoning"), ("LLM05", "Improper Output Handling"), ("LLM06", "Excessive Agency"),
            ("LLM07", "System Prompt Leakage"), ("LLM08", "Vector and Embedding Weaknesses"), ("LLM09", "Misinformation"),
            ("LLM10", "Unbounded Consumption"),
        ],
    },
    "CIS_V8": {
        "name": "CIS Critical Security Controls v8",
        "short": "CIS v8",
        "items": [
            ("CIS 1", "Inventory and Control of Enterprise Assets"), ("CIS 2", "Inventory and Control of Software Assets"), ("CIS 3", "Data Protection"),
            ("CIS 4", "Secure Configuration of Enterprise Assets and Software"), ("CIS 5", "Account Management"), ("CIS 6", "Access Control Management"),
            ("CIS 7", "Continuous Vulnerability Management"), ("CIS 8", "Audit Log Management"), ("CIS 9", "Email and Web Browser Protections"),
            ("CIS 10", "Malware Defenses"), ("CIS 11", "Data Recovery"), ("CIS 12", "Network Infrastructure Management"),
            ("CIS 13", "Network Monitoring and Defense"), ("CIS 14", "Security Awareness and Skills Training"), ("CIS 15", "Service Provider Management"),
            ("CIS 16", "Application Software Security"), ("CIS 17", "Incident Response Management"), ("CIS 18", "Penetration Testing"),
        ],
    },
    "GDPR": {
        "name": "EU General Data Protection Regulation",
        "short": "GDPR",
        "items": [
            ("Art. 5", "Principles relating to processing of personal data"), ("Art. 6", "Lawfulness of processing"), ("Art. 22", "Automated individual decision-making"),
            ("Art. 25", "Data protection by design and by default"), ("Art. 28", "Processor obligations"), ("Art. 30", "Records of processing activities"),
            ("Art. 32", "Security of processing"), ("Art. 33", "Notification of a personal data breach to the supervisory authority (72h)"),
            ("Art. 35", "Data protection impact assessment"), ("Art. 44", "Transfers of personal data to third countries"),
        ],
    },
}

# MITRE ATT&CK (Enterprise) and MITRE ATLAS (AI) technique references used by the scenario library.
ATTACK_TECHNIQUES = {
    "T1566": "Phishing", "T1566.002": "Phishing: Spearphishing Link", "T1486": "Data Encrypted for Impact", "T1078": "Valid Accounts",
    "T1078.004": "Valid Accounts: Cloud Accounts", "T1195": "Supply Chain Compromise", "T1195.002": "Compromise Software Supply Chain",
    "T1530": "Data from Cloud Storage", "T1552": "Unsecured Credentials", "T1552.001": "Credentials In Files", "T1190": "Exploit Public-Facing Application",
    "T1110": "Brute Force", "T1110.004": "Credential Stuffing", "T1498": "Network Denial of Service", "T1499": "Endpoint Denial of Service",
    "T1567": "Exfiltration Over Web Service", "T1098": "Account Manipulation", "T1048": "Exfiltration Over Alternative Protocol",
    "T1059": "Command and Scripting Interpreter", "T1621": "Multi-Factor Authentication Request Generation", "T1213": "Data from Information Repositories",
    "T1083": "File and Directory Discovery", "T1199": "Trusted Relationship", "T1537": "Transfer Data to Cloud Account", "T1580": "Cloud Infrastructure Discovery",
    # MITRE ATLAS
    "AML.T0051": "LLM Prompt Injection", "AML.T0054": "LLM Jailbreak", "AML.T0020": "Poison Training Data", "AML.T0010": "ML Supply Chain Compromise",
    "AML.T0024": "Exfiltration via ML Inference API", "AML.T0043": "Craft Adversarial Data", "AML.T0056": "LLM Meta Prompt Extraction",
    "AML.T0029": "Denial of ML Service", "AML.T0053": "LLM Plugin Compromise",
}

RISK_CATEGORIES = [
    "Cyber Security", "AI / Model", "Cloud & Infrastructure", "Third Party", "Data Privacy", "Compliance & Legal",
    "Operational", "People & Insider", "Financial",
]


def framework_catalog() -> list[dict]:
    return [
        {"key": k, "name": v["name"], "short": v["short"], "items": [{"id": i, "name": n} for i, n in v["items"]]}
        for k, v in FRAMEWORKS.items()
    ]


def lookup(framework: str, item_id: str) -> str | None:
    fw = FRAMEWORKS.get(framework)
    if not fw:
        return None
    for i, n in fw["items"]:
        if i == item_id:
            return n
    return None
