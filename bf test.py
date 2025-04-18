import requests

url = "http://localhost:5001/analyze"
data = {"request_data": "test"}
headers = {"Content-Type": "application/json"}

for i in range(15):  # Send 15 requests
    response = requests.post(url, json=data, headers=headers)
    print(f"Request {i+1}: {response.status_code} - {response.text}")