# -*- coding: utf-8 -*-
# @Author      : LJQ
# @Time        : 2023/3/10 16:59
# @Version     : Python 3.6.4
import math

from simple_tools.patterns import FlyWeight

try:
    import pymongo
except ImportError:
    pass
else:
    class _MongoDBClient(metaclass=FlyWeight):
        def __init__(self, mongodb_url: str):
            self.mongo = pymongo.MongoClient(mongodb_url)


    def client(mongodb_url: str) -> pymongo.MongoClient:
        return _MongoDBClient(mongodb_url).mongo


    def safe_bulk_write(collection, operators: list, batch_size: int = 1000, ordered: bool = False):
        for index in range(math.ceil(len(operators) / batch_size)):
            collection.bulk_write(operators[index * batch_size: (index + 1) * batch_size], ordered=ordered)
