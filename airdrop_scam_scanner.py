"""
Airdrop Scam Scanner — утилита для обнаружения подозрительных токенов в Ethereum-кошельке,
часто используемых в фишинговых и airdrop-скамах.
"""

import requests
import argparse


ETHERSCAN_API = "https://api.etherscan.io/api"


def fetch_token_transfers(address, api_key):
    params = {
        "module": "account",
        "action": "tokentx",
        "address": address,
        "startblock": 0,
        "endblock": 99999999,
        "sort": "desc",
        "apikey": api_key
    }
    r = requests.get(ETHERSCAN_API, params=params)
    return r.json().get("result", [])


def detect_scam_tokens(transfers):
    seen = {}
    suspicious = []

    for tx in transfers:
        token = tx.get("tokenName", "")
        symbol = tx.get("tokenSymbol", "")
        contract = tx.get("contractAddress", "")
        to = tx.get("to", "")
        from_address = tx.get("from", "")

        key = f"{token}::{symbol}::{contract}"
        if key in seen:
            continue
        seen[key] = True

        # Heuristics for suspicious airdrops
        if from_address.lower().startswith("0x000") or from_address.lower() == to.lower():
            suspicious.append((token, symbol, contract, "Airdrop с нулевого адреса"))

        if token.lower().count("airdrop") or token.lower().count("claim"):
            suspicious.append((token, symbol, contract, "Название содержит 'airdrop' или 'claim'"))

        if len(token) > 25 or len(symbol) > 10:
            suspicious.append((token, symbol, contract, "Слишком длинное имя токена или символ"))

    return suspicious


def main():
    parser = argparse.ArgumentParser(description="Поиск подозрительных airdrop-токенов в кошельке.")
    parser.add_argument("address", help="Ethereum адрес")
    parser.add_argument("api_key", help="Etherscan API ключ")
    args = parser.parse_args()

    print("[•] Получаем токен-трансферы...")
    txs = fetch_token_transfers(args.address, args.api_key)

    print(f"[✓] Найдено токенов: {len(txs)}. Анализ...")
    results = detect_scam_tokens(txs)

    print("\nРезультаты анализа:")
    if not results:
        print("✓ Подозрительные токены не найдены.")
    else:
        for name, symbol, contract, reason in results:
            print(f"- {name} ({symbol}) | {contract} → {reason}")


if __name__ == "__main__":
    main()
