# -*- coding: utf-8 -*-
# @Author      : LJQ
# @Time        : 2023/3/10 16:40
# @Version     : Python 3.6.4
import datetime
import functools
import importlib
import inspect
import logging
import math
import multiprocessing
import os
import platform
import random
import socket
import sys
import threading
import time
from pathlib import Path

from requests.cookies import RequestsCookieJar
from requests.utils import cookiejar_from_dict, dict_from_cookiejar

from simple_tools.algorithms import md5

logger = logging.getLogger(__name__)


def is_windows() -> bool:
    return platform.system().lower() == 'windows'


IS_WINDOWS = is_windows()


def _get_extranet_ip() -> str:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]

    return ip


# 网络中断时,会产生OSError: [Errno 101] Network is unreachable异常,导致网络服务线程结束,进而重启失败,网络服务停止
EXTRANET_IP = _get_extranet_ip()


def is_subprocess() -> bool:
    """
    判断当前进程是否为子进程
    :return:
    """
    if sys.version_info >= (3, 8):
        return bool(multiprocessing.process.parent_process())
    else:
        cur_process = multiprocessing.current_process().name
        return cur_process != 'MainProcess'


def makekeys(args: tuple, kwargs: dict) -> tuple:
    """
    将关键字参数与排序与元组拼接
    Args:
        args: 位置参数
        kwargs: 关键字参数
    Returns: 拼接后的元组
    """
    for item in sorted(kwargs.items(), key=lambda x: x[0]):
        args += tuple(item)
    return args


def ciphers(length: int, base: str = '0123456789abcdef') -> str:
    seed = math.ceil(length / len(base)) * base
    return ''.join(random.sample(seed, length))


def build_key(provider: str = '', unique_id: str = '', suffix: str = ''):
    return '_'.join(filter(bool, [provider, unique_id, suffix]))


def has_drm_decrypted(encrypt_file: str, decrypt_file: str):
    # AES-CBC模式必须使用填充,因此加密后的文件长度比解密的文件长度大.
    # AES-CTR模式不使用填充,因此加密后的文件长度和解密的文件长度相同.
    # 因此通过`截取文件后10M并比较MD5值`的方式来判断是否解密成功
    encrypt_size = os.path.getsize(encrypt_file)
    decrypt_size = os.path.getsize(decrypt_file)
    if encrypt_size != decrypt_size:
        return True
    read_size = 10 * 1024 * 1024
    with open(encrypt_file, mode='rb') as f:
        f.seek(max(0, encrypt_size - read_size))
        encrypt_md5 = md5(f.read())
    with open(decrypt_file, mode='rb') as f:
        f.seek(max(0, decrypt_size - read_size))
        decrypt_md5 = md5(f.read())
    return encrypt_md5 != decrypt_md5


class CookieConverter(object):
    @staticmethod
    def get_cookie_str(cookies) -> str:
        if not cookies:
            return ''
        if isinstance(cookies, RequestsCookieJar):
            cookies = dict_from_cookiejar(cookies)
        cookie = '; '.join([f'{k}={v}' for k, v in cookies.items()])
        return cookie

    @staticmethod
    def get_cookie_dict(cookies) -> dict:
        if not cookies:
            return {}
        if isinstance(cookies, str):
            cookie_dict = {}
            for cookie_pair in cookies.split('; '):
                k, v = cookie_pair.split('=', 1)
                cookie_dict[k] = v
            return cookie_dict
        elif isinstance(cookies, RequestsCookieJar):
            return dict_from_cookiejar(cookies)
        elif isinstance(cookies, dict):
            return cookies

    @staticmethod
    def get_cookiejar(cookies) -> RequestsCookieJar:
        if isinstance(cookies, str):
            cookies = CookieConverter.get_cookie_dict(cookies)
        if isinstance(cookies, dict):
            cookies = cookiejar_from_dict(cookies)
        return cookies


class Clock(object):

    @staticmethod
    def date() -> str:
        return time.strftime('%Y-%m-%d %H:%M:%S')

    @staticmethod
    def timestamp() -> int:
        return int(time.time())

    @staticmethod
    def millisecond() -> int:
        return int(time.time() * 1000)

    @staticmethod
    def date_to_timestamp(date: str, fmt: str = '%Y-%m-%d %H:%M:%S') -> float:
        if not date:
            return 0
        if isinstance(date, float):
            return date
        return time.mktime(time.strptime(date, fmt))

    @staticmethod
    def timestamp_to_date(timestamp: int, fmt: str = '%Y-%m-%d %H:%M:%S') -> str:
        if not timestamp:
            return ''
        if isinstance(timestamp, str):
            return timestamp
        return time.strftime(fmt, time.localtime(timestamp))


class FunctionResult(object):
    _caches = {}

    @classmethod
    def cache(cls, duration: float):
        def _cache(func):
            @functools.wraps(func)
            def __cache(*args, **kwargs):
                if not hasattr(func, '__function_result_lock'):
                    func.__function_result_lock = threading.RLock()
                key = func, makekeys(args, kwargs)
                if key not in cls._caches or time.time() - cls._caches[key][1] > duration:
                    with func.__function_result_lock:
                        result = func(*args, **kwargs)
                        cls._caches[key] = result, time.time()
                return cls._caches[key][0]

            return __cache

        return _cache


def get_plugin_map(base_cls: type, filter_stems: tuple = None):
    module = base_cls.__module__
    clc_file = Path(inspect.getfile(base_cls))
    if filter_stems is None:
        filter_stems = '__init__', clc_file.stem
    for file in clc_file.parent.iterdir():
        if file.is_file() and file.suffix == '.py' and file.stem not in filter_stems:
            try:
                importlib.import_module(f'{module}.{file.stem}')
            except Exception as e:
                logger.exception(e)
    plugin_map = {}

    def fill_support_plugin(cls):
        for subclass in cls.__subclasses__():
            if subclass.__subclasses__():
                fill_support_plugin(subclass)
            else:
                usable = getattr(subclass, 'usable', None)
                if not usable:
                    continue
                provider = getattr(subclass, 'provider', None)
                if not isinstance(provider, str):
                    provider = subclass.__module__.rsplit('.', 1)[-1]
                plugin_map[provider] = subclass

    fill_support_plugin(base_cls)
    return dict(sorted(plugin_map.items(), key=lambda x: x[0]))


def get_subclasses(base_cls: type):
    subclasses = {}

    def fill_subclasses(cls):
        for subclass in cls.__subclasses__():
            if subclass.__subclasses__():
                fill_subclasses(subclass)
            else:
                usable = getattr(subclass, 'usable', None)
                if not usable:
                    continue
                subclasses[subclass.__name__] = subclass

    fill_subclasses(base_cls)
    return dict(sorted(subclasses.items(), key=lambda x: x[0]))


class CPUTimer(object):
    """
    CPU计时器(上下文管理器)
    当前线程在某一时间段内的CPU利用率计算公式:
        CPU利用率 = CPU时间 / 运行时间 * 100%
    """

    def __init__(self, tag: str = ''):
        if tag:
            tag = f'<{tag}> '
        self.tag = tag

    def __enter__(self):
        self.start = time.time()
        self.thread_clock_id = time.CLOCK_THREAD_CPUTIME_ID
        self.thread_cpu_start = time.clock_gettime(self.thread_clock_id)

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.thread_cpu_end = time.clock_gettime(self.thread_clock_id)
        self.end = time.time()
        thread_cpu_duration = self.thread_cpu_end - self.thread_cpu_start
        duration = self.end - self.start
        logger.warning(
            f'{self.tag}'
            f'CPU利用率: {round(100 * thread_cpu_duration / duration, 2)}%, '
            f'CPU时间: {round(thread_cpu_duration, 8)}, 运行时间: {round(duration, 8)}'
        )


class Timer(object):
    """
    计时器(上下文管理器)
    """

    def __init__(self, tag: str = ''):
        if tag:
            tag = f'<{tag}> '
        self.tag = tag

    def __enter__(self):
        self.start = datetime.datetime.now().replace(microsecond=0)

    def __exit__(self, exc_type, exc_val, exc_tb):
        self.end = datetime.datetime.now().replace(microsecond=0)
        logger.info(f'{self.tag}总共耗时: {self.end - self.start}')
