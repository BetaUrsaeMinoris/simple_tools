# -*- coding: utf-8 -*-
# @Author      : LJQ
# @Time        : 2023/3/10 16:56
# @Version     : Python 3.6.4
import threading

from simple_tools.commons import makekeys


class FlyWeight(type):
    """
    享元模式
    """

    def __call__(cls, *args, **kwargs):
        if not hasattr(cls, '_flyweight_lock'):
            cls._flyweight_lock = threading.RLock()
            cls._instances = {}
        with cls._flyweight_lock:
            keys = makekeys(args, kwargs)
            if keys not in cls._instances:
                cls._instances[keys] = super().__call__(*args, **kwargs)
        return cls._instances[keys]
