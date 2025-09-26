from __future__ import annotations

from typing import Callable, Awaitable

from steampy.exceptions import LoginRequired


def async_login_required(func: Callable[..., Awaitable]):
    async def func_wrapper(self, *args, **kwargs):
        if not getattr(self, 'was_login_executed', False):
            raise LoginRequired('Use login method first')
        return await func(self, *args, **kwargs)

    return func_wrapper


