import requests

API_TOKEN = "3IZ8eFJ78qAkgoV"

HEADERS = {"Authorization": f"Bearer {API_TOKEN}", "Content-Type": "application/json"}


def send_sms(phone_list: list[str], message_text: str, sender: str = "Vebinar") -> dict:
    payload = {"phone": phone_list, "message": message_text, "src_addr": sender}

    try:
        response = requests.post(
            "https://im.smsclub.mobi/sms/send", json=payload, headers=HEADERS
        )
        response.raise_for_status()
        return response.json()
    except requests.exceptions.RequestException as e:
        return {
            "error": str(e),
            "raw": response.text if "response" in locals() else None,
        }
