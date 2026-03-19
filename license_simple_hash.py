import json,base64,hashlib

secret="MY_SUPER_SECRET"

with open("license_data.json", "r") as f:
    license_data = json.load(f)

json_payload = json.dumps(license_data, separators=(',',':'))
payload_b64 = base64.b64encode(json_payload.encode()).decode()
sig = hashlib.sha256((payload_b64 + ":" + secret).encode()).hexdigest()
token = payload_b64 + "." + sig
print(token)