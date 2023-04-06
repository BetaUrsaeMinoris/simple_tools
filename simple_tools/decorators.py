# -*- coding: utf-8 -*-
# @Author      : LJQ
# @Time        : 2023/3/17 16:16
# @Version     : Python 3.6.4
import functools
import json
import logging
import time
from functools import singledispatch
from pathlib import Path
from threading import Thread

logger = logging.getLogger(__name__)


@singledispatch
def circulate(*args, **kwargs):
    registers = [register.__name__ for register in circulate.registry if register.__name__ != 'object']
    logger.info(f'请使用合适的参数, 如: {", ".join(registers)} 不能是: {args, kwargs}')

    def _circulate(func):
        return func

    return _circulate


@circulate.register(Path)
def circulate_register(file: Path, key: str = None, is_block: bool = True):
    """
    key为file的直接索引, 如: a或a.b.c.d
    :param file:
    :param key:
    :param is_block:
    :return:
    """

    def _circulate(func):

        @functools.wraps(func)
        def __circulate(*args, **kwargs):
            def ___circulate():
                logger.info(f'使用配置文件可变间隔方式轮询程序')
                while True:
                    interval = 5
                    try:
                        data = json.loads(file.read_text('utf-8'))
                        if key is not None:
                            top_index = key.split('.')[0]
                            if top_index not in data:
                                top_index = 'default'
                            data = data[top_index]
                        data = data[func.__name__]
                        interval = max(1, data['interval'])
                        usable = data['usable']
                        logger.info(f'正在运行函数: {func.__name__}, key: {key}, interval: {interval}, usable: {usable}')
                        if usable:
                            func(*args, **kwargs)
                    except Exception as e:
                        logger.error(f'error: {e}')
                    time.sleep(interval)

            if is_block:
                return ___circulate()
            else:
                Thread(target=___circulate).start()

        return __circulate

    return _circulate


@circulate.register(int)
def circulate_register(sleep: int = 1, is_block: bool = True):
    def _circulate(func):

        @functools.wraps(func)
        def __circulate(*args, **kwargs):
            def ___circulate():
                logger.info(f'使用固定间隔方式轮询程序')
                while True:
                    try:
                        func(*args, **kwargs)
                    except Exception as e:
                        logger.exception(f'error: {e}')
                    time.sleep(sleep)

            if is_block:
                return ___circulate()
            else:
                Thread(target=___circulate).start()

        return __circulate

    return _circulate


def run(times: int = 1, sleep_time: int = 1, is_throw_error: bool = True):
    """
    运行装饰器, 最多运行 times 次
    """

    def _run(func):
        @functools.wraps(func)
        def __run(*args, **kwargs):
            for t in range(times):
                try:
                    result = func(*args, **kwargs)
                except Exception as e:
                    if t == times - 1 and is_throw_error:
                        raise e
                else:
                    return result
                time.sleep(sleep_time)

        return __run

    return _run


def timer(func):
    """
    计时器装饰器
    """

    @functools.wraps(func)
    def _timer(*args, **kwargs):
        start_time = time.time()
        result = func(*args, **kwargs)
        end_time = time.time()
        duration = f'{end_time - start_time:.3f} s'
        return duration, result

    return _timer


def forever(sleep_time: float = 60):
    """
    永不停止装饰器
    :return:
    """

    def outer(func):

        @functools.wraps(func)
        def inner(*args, **kwargs):
            if isinstance(sleep_time, (float, int)) and sleep_time > 0:
                logger.info(f'{func.__name__} {sleep_time}s 后运行')
                time.sleep(sleep_time)
            else:
                logger.info(f'{func.__name__} 正在运行')
            while True:
                try:
                    func(*args, **kwargs)
                except Exception as e:
                    logger.exception(f'{func.__name__}程序异常: {e}')
                time.sleep(sleep_time)

        return inner

    return outer
