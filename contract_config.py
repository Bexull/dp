import json

with open("artifacts/contracts/URLComplaint.json", "r") as f:
    contract_data = json.load(f)

# Проверь, что contract_data — это словарь и у него есть ключ "abi"
if isinstance(contract_data, dict) and "abi" in contract_data:
    CONTRACT_ABI = contract_data["abi"]
else:
    raise ValueError("Неверный формат ABI! Проверь JSON-файл.")
