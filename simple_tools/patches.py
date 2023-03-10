# -*- coding: utf-8 -*-
# @Author      : LJQ
# @Time        : 2023/3/10 16:59
# @Version     : Python 3.6.4
import functools

import requests


def patch_requests(timeout: (float, tuple) = 60):
    """
    自动填充timeout参数, 默认设置60s
    """
    # 优先使用已设置的超时, 如requests.get(timeout=5)超时为5, requests.get()超时为默认值60
    requests.Session.request = functools.partialmethod(requests.Session.request, timeout=timeout)
