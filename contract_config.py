import json

CONTRACT_ADDRESS = "0x7d5736Ac4E2d4C8b66aAFE2f918a472323321D86"

with open("contract_abi.json", "r") as f:
    CONTRACT_ABI = json.load(f)["abi"]
