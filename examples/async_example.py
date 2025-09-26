from __future__ import annotations

import re
from asyncio import run

from better_proxy import Proxy

from steampy.async_client import AsyncSteamClient as SteamSDK
from steampy.models import GameOptions


class Account:
    def __init__(self, id: int, steam_api_key: str, steam_username: str, steam_password: str, proxy: Proxy | None = None) -> None:
        self.id = id
        self.steam_api_key = steam_api_key
        self.steam_username = steam_username
        self.steam_password = steam_password
        self.proxy = proxy

    @property
    def proxy_dict(self) -> dict | None:
        if not self.proxy:
            return None
        return self.proxy.as_proxies_dict  # type: ignore[attr-defined]


class SteamClient:
    def __init__(self, account: Account):
        self.account = account
        self.client = SteamSDK(account.steam_api_key, proxies=account.proxy_dict)

    async def login(self):
        await self.client.login(
            self.account.steam_username,
            self.account.steam_password,
            '{"shared_secret":"...","identity_secret":"...","steamid":"..."}',
        )

    async def accept_all_donation_offers(self):
        offers_response = (await self.client.api_call('GET', 'IEconService', 'GetTradeOffers', 'v1', {
            'key': self.account.steam_api_key,
            'get_received_offers': 1,
            'get_sent_offers': 0,
            'get_descriptions': 1,
            'language': 'english',
            'active_only': 1,
            'historical_only': 0,
        })).json()
        offers = offers_response['response'].get('trade_offers_received', [])
        for offer in offers:
            if self._is_donation(offer):
                offer_id = offer['tradeofferid']
                # Accept via community endpoint
                await self.client.accept_trade_offer(offer_id)  # to be implemented if needed

    def _is_donation(self, offer: dict) -> bool:
        from steampy.models import TradeOfferState
        return (
            offer.get('items_to_receive')
            and not offer.get('items_to_give')
            and offer['trade_offer_state'] == TradeOfferState.Active
            and not offer['is_our_offer']
        )

    async def load_inventory(self):
        inventory = await self.client.get_my_inventory(GameOptions.CS)
        return inventory

    async def check_balance(self):
        balance = await self.client.get_wallet_balance(convert_to_decimal=True)
        return balance

    async def check_item_price(self, name: str):
        price = await self.client.market.fetch_price(item_hash_name=name, game=GameOptions.CS)
        match = re.search(r"[\d,.]+", price.get('median_price', ''))
        return float(match.group().replace(',', '')) if match else None

    async def get_average_price_by_period(self, name: str, period: int):
        history_resp = await self.client.market.fetch_price_history(item_hash_name=name, game=GameOptions.CS)
        history = history_resp.get('prices') or []
        if not history or len(history) < period:
            return 0
        recent_entries = history[-period:]
        prices = [entry[1] for entry in recent_entries]
        return sum(prices) / len(prices)

    @property
    def login_cookies(self):
        return self.client.login_cookies


async def main():
    account = Account(
        id=1,
        proxy=Proxy.from_str("http://user:pass@1.2.3.4:5678"),
        steam_api_key="YOUR_KEY",
        steam_username="login",
        steam_password="password",
    )
    client = SteamClient(account)
    await client.login()
    _ = await client.load_inventory()
    balance = await client.check_balance()
    print(balance)
    test_item_price = await client.check_item_price('M4A1-S | Cyrex (Factory New)')
    print(test_item_price)
    average_price = await client.get_average_price_by_period('M4A1-S | Cyrex (Factory New)', 10)
    print(average_price)


if __name__ == "__main__":
    run(main())


