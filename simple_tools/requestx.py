# -*- coding: utf-8 -*-
# @Author      : LJQ
# @Time        : 2023/3/10 18:52
# @Version     : Python 3.6.4
import time

import requests


class Sessionx(requests.Session):
    def request(self, method, url, **kwargs) -> requests.Response:
        """
        expression: 异常状态码重试
        """
        retry = kwargs.pop('retry', 3)
        sleep = kwargs.pop('sleep', 3)
        expression = kwargs.pop('expression', lambda x: False)
        error = None
        for _ in range(retry):
            try:
                resp = super().request(method, url, **kwargs)
                if expression(resp.status_code):
                    time.sleep(sleep)
                    continue
                break
            except requests.exceptions.RequestException as e:
                error = e
                continue
        else:
            raise error
        return resp

    def requestx(self, method, urls, **kwargs) -> requests.Response:
        kwargs['timeout'] = kwargs.get('timeout') or 30
        error = None
        for url in urls:
            try:
                resp = self.request(method, url, **kwargs)
                break
            except requests.exceptions.RequestException as e:
                error = e
                continue
        else:
            raise error
        return resp
