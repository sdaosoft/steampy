from __future__ import annotations

import re
import urllib.parse as urlparse

from curl_cffi.requests import AsyncSession
from bs4 import BeautifulSoup
from curl_cffi.curl import CurlMime

from steampy import guard
from steampy.async_login import AsyncLoginExecutor
from steampy.async_market import AsyncSteamMarket
from steampy.exceptions import InvalidCredentials
from steampy.models import GameOptions, SteamUrl
from steampy.async_utils import async_login_required
from steampy.utils import (
    merge_items_with_descriptions_from_inventory,
    text_between,
)
import re
import json
from decimal import Decimal
from steampy.async_confirmation import AsyncConfirmationExecutor


class AsyncSteamClient:
    def __init__(self, api_key: str, username: str | None = None, password: str | None = None, steam_guard: str | None = None, login_cookies: dict | None = None, proxies: dict | None = None) -> None:
        self._api_key = api_key
        self._session = AsyncSession()

        if proxies:
            self._session.proxies.update(proxies)

        self.steam_guard_string = steam_guard
        if self.steam_guard_string is not None:
            self.steam_guard = guard.load_steam_guard(self.steam_guard_string)
        else:
            self.steam_guard = None

        self.was_login_executed = False
        self.username = username
        self._password = password
        self.market = AsyncSteamMarket(self._session)
        self._access_token = None

        if login_cookies:
            self.set_login_cookies(login_cookies)

    def set_login_cookies(self, cookies: dict) -> None:
        self._session.cookies.update(cookies)
        self.was_login_executed = True
        if self.steam_guard is None:
            self.steam_guard = {'steamid': str(self.get_steam_id())}
        self.market._set_login_executed(self.steam_guard, self._get_session_id())

    @async_login_required
    async def get_steam_id(self) -> int:
        url = SteamUrl.COMMUNITY_URL
        response = await self._session.get(url)
        if steam_id := re.search(r'g_steamID = "(\d+)";', response.text):
            return int(steam_id.group(1))
        raise ValueError(f'Invalid steam_id: {steam_id}')

    async def login(self, username: str | None = None, password: str | None = None, steam_guard: str | None = None) -> None:
        invalid_client_credentials_is_present = None in {self.username, self._password, self.steam_guard_string}
        invalid_login_credentials_is_present = None in {username, password, steam_guard}

        if invalid_client_credentials_is_present and invalid_login_credentials_is_present:
            raise InvalidCredentials('You have to pass username, password and steam_guard parameters when using "login" method')

        if invalid_client_credentials_is_present:
            self.steam_guard_string = steam_guard
            self.steam_guard = guard.load_steam_guard(self.steam_guard_string)
            self.username = username
            self._password = password

        if self.was_login_executed:
            return

        self._session.cookies.set('steamRememberLogin', 'true')
        await AsyncLoginExecutor(self.username, self._password, self.steam_guard['shared_secret'], self._session).login()
        self.was_login_executed = True
        self.market._set_login_executed(self.steam_guard, self._get_session_id())
        self._access_token = self._set_access_token()

    def _set_access_token(self) -> str:
        cookie_value = self._session.cookies.get_dict().get('steamLoginSecure')
        if not cookie_value:
            raise ValueError('steamLoginSecure cookie not present')
        decoded_cookie_value = urlparse.unquote(cookie_value)
        access_token_parts = decoded_cookie_value.split('||')
        if len(access_token_parts) < 2:
            raise ValueError('Access token not found in steamLoginSecure cookie')
        access_token = access_token_parts[1]
        return access_token

    @async_login_required
    async def is_session_alive(self) -> bool:
        steam_login = self.username
        main_page_response = await self._session.get(SteamUrl.COMMUNITY_URL)
        return steam_login.lower() in main_page_response.text.lower()

    async def api_call(self, method: str, interface: str, api_method: str, version: str, params: dict | None = None):
        url = f'{SteamUrl.API_URL}/{interface}/{api_method}/{version}'
        response = await (self._session.get(url, params=params) if method == 'GET' else self._session.post(url, data=params))
        return response

    @async_login_required
    async def openid_authenticate(self, loginform_url: str, user_agent: str | None = None) -> str:
        """Complete OpenID auth flow for external site using an incoming Steam loginform URL.

        Steps:
        - GET the `loginform_url` from the relying party (e.g., skinflow) which is hosted on steamcommunity.com
        - Parse the form to extract `openidparams` and `nonce`
        - Ensure `sessionidSecureOpenIDNonce` cookie is present (set from `nonce` if missing)
        - POST to `https://steamcommunity.com/openid/login` with urlencoded data to authorize
        - Follow the 302 Location back to the relying party and return the final URL
        """
        headers = {
            'accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7',
            'accept-language': 'en-US,en;q=0.9',
            'upgrade-insecure-requests': '1',
        }
        if user_agent:
            headers['user-agent'] = user_agent

        # Fetch login form page (steamcommunity.com/openid/loginform)
        form_resp = await self._session.get(loginform_url, headers=headers)
        soup = BeautifulSoup(form_resp.text, 'html.parser')
        form = soup.find('form', {'id': 'openidForm'})
        if not form:
            raise ValueError('openidForm not found on login form page')
        openidparams_input = form.find('input', {'name': 'openidparams'})
        nonce_input = form.find('input', {'name': 'nonce'})
        if not openidparams_input or not nonce_input:
            raise ValueError('Required inputs (openidparams, nonce) not found on login form page')
        openidparams = openidparams_input['value']
        nonce = nonce_input['value']

        # Ensure sessionidSecureOpenIDNonce cookie
        if 'sessionidSecureOpenIDNonce' not in self._session.cookies.get_dict():
            self._session.cookies.set('sessionidSecureOpenIDNonce', nonce, domain='steamcommunity.com')

        # Submit OpenID authorization (multipart/form-data to match browser)
        mime = CurlMime()
        mime.addpart(name='action', data='steam_openid_login')
        mime.addpart(name='openid.mode', data='checkid_setup')
        mime.addpart(name='openidparams', data=openidparams)
        mime.addpart(name='nonce', data=nonce)
        post_headers = {
            'Accept': headers['accept'],
            'Accept-Language': headers['accept-language'],
            'Origin': 'https://steamcommunity.com',
            'Referer': loginform_url,
        }
        if user_agent:
            post_headers['User-Agent'] = user_agent
        post_resp = await self._session.post('https://steamcommunity.com/openid/login', multipart=mime, headers=post_headers, allow_redirects=False)
        if post_resp.status_code != 302 or 'Location' not in post_resp.headers:
            raise ValueError(f'Unexpected response from OpenID login: {post_resp.status_code}')

        redirect_url = post_resp.headers['Location']
        final = await self._session.get(redirect_url, allow_redirects=True)
        return final.url

    @async_login_required
    async def get_my_inventory(self, game: GameOptions, merge: bool = True, count: int = 5000) -> dict:
        steam_id = self.steam_guard['steamid']
        return await self.get_partner_inventory(steam_id, game, merge, count)

    @async_login_required
    async def get_partner_inventory(self, partner_steam_id: str, game: GameOptions, merge: bool = True, count: int = 5000) -> dict:
        url = f'{SteamUrl.COMMUNITY_URL}/inventory/{partner_steam_id}/{game.app_id}/{game.context_id}'
        params = {'l': 'english', 'count': count}
        full_response = await self._session.get(url, params=params)
        response_dict = full_response.json()
        if full_response.status_code == 429:
            raise Exception('Too many requests, try again later.')
        if response_dict is None or response_dict.get('success') != 1:
            raise Exception('Success value should be 1.')
        return merge_items_with_descriptions_from_inventory(response_dict, game) if merge else response_dict

    def _get_session_id(self) -> str:
        return self._session.cookies.get_dict(domain="steamcommunity.com", path="/").get('sessionid')

    @property
    def login_cookies(self):
        return self._session.cookies

    async def accept_trade_offer(self, trade_offer_id: str) -> dict:
        # Fetch partner id to set Referer and perform community accept
        url = f'{SteamUrl.COMMUNITY_URL}/tradeoffer/{trade_offer_id}'
        offer_response_text = (await self._session.get(url)).text
        if 'You have logged in from a new device. In order to protect the items' in offer_response_text:
            raise Exception("Account has logged in a new device and can't trade for 7 days")
        partner_id = re.search(r"var g_ulTradePartnerSteamID = '([0-9]+)';", offer_response_text).group(1)
        session_id = self._get_session_id()
        accept_url = f'{SteamUrl.COMMUNITY_URL}/tradeoffer/{trade_offer_id}/accept'
        params = {
            'sessionid': session_id,
            'tradeofferid': trade_offer_id,
            'serverid': '1',
            'partner': partner_id,
            'captcha': '',
        }
        headers = {
            'Referer': f'{SteamUrl.COMMUNITY_URL}/tradeoffer/{trade_offer_id}',
            'Content-Type': 'application/x-www-form-urlencoded; charset=UTF-8',
            'Origin': SteamUrl.COMMUNITY_URL
        }
        response = (await self._session.post(accept_url, data=params, headers=headers)).json()
        if response.get('needs_mobile_confirmation', False):
            confirmation_executor = AsyncConfirmationExecutor(
                self.steam_guard['identity_secret'], self.steam_guard['steamid'], self._session,
            )
            return await confirmation_executor.send_trade_allow_request(trade_offer_id)
        return response

    @async_login_required
    async def get_wallet_balance(self, convert_to_decimal: bool = True, on_hold: bool = False):
        response = await self._session.get(f'{SteamUrl.COMMUNITY_URL}/market')
        wallet_info_match = re.search(r'var g_rgWalletInfo = (.*?);', response.text)
        if wallet_info_match:
            balance_dict_str = wallet_info_match.group(1)
            balance_dict = json.loads(balance_dict_str)
        else:
            raise Exception('Unable to get wallet balance string match')
        balance_dict_key = 'wallet_delayed_balance' if on_hold else 'wallet_balance'
        if convert_to_decimal:
            return Decimal(balance_dict[balance_dict_key]) / 100
        return balance_dict[balance_dict_key]


