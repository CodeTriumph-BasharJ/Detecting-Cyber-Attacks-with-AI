This project involves the development of four specialized agents, each dedicated to analyzing a specific type of cyberattack:
Brute-force attacks,
Data exfiltration attacks,
Lateral movement attacks, and
Privilege escalation attacks

Attack incidents are stored in JSON format and embedded within each agent as simplified YAML text. This approach improves the agents' ability to process and understand incident data while maximizing the accuracy of incident separation, ensuring that distinct events occurring at different times within the same attack category are correctly identified and analyzed.

A separate mitigation agent is responsible for generating remediation and mitigation recommendations for each attack type. This agent leverages a trusted PDF document containing industry-approved mitigation strategies. Retrieval-Augmented Generation (RAG) techniques are applied during the PDF embedding process to ensure that all mitigation recommendations are strictly derived from the approved source material and do not include information outside the document's scope.

To maintain reliability and consistency, all cyberattack analysis and mitigation agents operate under strict, hard-coded rules. These controls are designed to minimize hallucinations, prevent responses that fall outside the defined attack parameters, and guarantee a consistent response structure across all user interactions.
