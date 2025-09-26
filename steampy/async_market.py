from __future__ import annotations

import json
import urllib.parse
from decimal import Decimal
from http import HTTPStatus

from curl_cffi.requests import AsyncSession

from steampy.exceptions import ApiException, TooManyRequests
from steampy.models import Currency, GameOptions, SteamUrl
from steampy.utils import (
    get_listing_id_to_assets_address_from_html,
    get_market_listings_from_html,
    get_market_sell_listings_from_api,
    login_required,
    merge_items_with_descriptions_from_listing,
    text_between,
)
from steampy.async_utils import async_login_required
from steampy.async_confirmation import AsyncConfirmationExecutor


class AsyncSteamMarket:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session
        self._steam_guard = None
        self._session_id = None
        self.was_login_executed = False

    def _set_login_executed(self, steamguard: dict, session_id: str) -> None:
        self._steam_guard = steamguard
        self._session_id = session_id
        self.was_login_executed = True

    async def fetch_price(self, item_hash_name: str, game: GameOptions, currency: Currency = Currency.USD, country='PL') -> dict:
        url = f'{SteamUrl.COMMUNITY_URL}/market/priceoverview/'
        params = {
            'country': country,
            'currency': currency.value,
            'appid': game.app_id,
            'market_hash_name': item_hash_name,
        }
        response = await self._session.get(url, params=params)
        if response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
            raise TooManyRequests('You can fetch maximum 20 prices in 60s period')
        return response.json()

    @async_login_required
    async def fetch_price_history(self, item_hash_name: str, game: GameOptions) -> dict:
        url = f'{SteamUrl.COMMUNITY_URL}/market/pricehistory/'
        params = {'country': 'PL', 'appid': game.app_id, 'market_hash_name': item_hash_name}
        response = await self._session.get(url, params=params)
        if response.status_code == HTTPStatus.TOO_MANY_REQUESTS:
            raise TooManyRequests('You can fetch maximum 20 prices in 60s period')
        return response.json()

    def _confirm_sell_listing(self, asset_id: str) -> dict:
        con_executor = AsyncConfirmationExecutor(
            self._steam_guard['identity_secret'], self._steam_guard['steamid'], self._session,
        )
        # Note: returned coroutine must be awaited by caller when this is used in async flow
        return con_executor.confirm_sell_listing(asset_id)


