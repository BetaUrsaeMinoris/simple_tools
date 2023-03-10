# -*- coding: utf-8 -*-
# @Author      : LJQ
# @Time        : 2023/3/10 16:59
# @Version     : Python 3.6.4
import pymongo

from simple_tools.patterns import FlyWeight


class _MongoDBClient(metaclass=FlyWeight):
    def __init__(self, mongodb_url: str):
        self.mongo = pymongo.MongoClient(mongodb_url)


def client(mongodb_url: str) -> pymongo.MongoClient:
    return _MongoDBClient(mongodb_url).mongo
