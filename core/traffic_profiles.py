TRAFFIC_PROFILES = {
    "icmp": {
        "name": "ICMP",
        "protocol": "ICMP",
        "description": "Basic ICMP connectivity traffic",
    },
    "web": {
        "name": "Web Browsing",
        "protocol": "TCP",
        "description": "HTTP request/response traffic",
    },
    "email": {
        "name": "E-mail",
        "protocol": "TCP",
        "description": "SMTP-like e-mail communication",
    },
    "voip": {
        "name": "VoIP",
        "protocol": "UDP",
        "description": "Continuous UDP voice-like traffic",
    },
    "whatsapp": {
        "name": "WhatsApp-like",
        "protocol": "TCP+UDP",
        "description": "Short burst messaging-like traffic",
    },
    "video": {
        "name": "Video Streaming",
        "protocol": "UDP",
        "description": "High-rate continuous streaming-like traffic",
    },
    "normal": {
        "name": "Normal Communication",
        "protocol": "TCP+UDP",
        "description": "Generic normal application communication",
    },
}


def get_profile(profile_name):
    return TRAFFIC_PROFILES.get(profile_name)


def list_profiles():
    return TRAFFIC_PROFILES