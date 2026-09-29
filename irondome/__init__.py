"""IronDome.ai core library.

Shared by the passive sensor (backend/sensor-service), the model training pipeline and the
traffic lab. Everything in this package is pure standard-library Python so the
sensor has no heavyweight dependencies:

    schema     - flow-record format, threat-class registry, standard alert schema
    netutil    - statistics, entropy, IP / domain helpers
    lexical    - DNS query-name lexical features (entropy, n-grams, dictionary cover)
    tls        - TLS ClientHello / ServerHello parsing and JA3 / JA3S / JA4 fingerprints
    features   - streaming (event-time windowed) feature extraction for all detectors
    traffic    - synthetic lab-traffic generators (benign + the six PS threat classes)
    pcap       - read-only PCAP / PCAPNG parsing, flow assembly, PCAP synthesis
    netflow    - NetFlow v5 decoding / encoding

Built for Smart India Hackathon problem statement 26145 (NTRO):
"AI-Based Detection of Cyber Threats in Unidirectional IP Traffic".
"""

__version__ = "2.0.0"
