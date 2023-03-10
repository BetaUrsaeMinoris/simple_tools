# -*- coding: utf-8 -*-
# @Author      : LJQ
# @Time        : 2023/3/10 17:01
# @Version     : Python 3.6.4
import abc
import typing


class DotDictWriter(dict):
    def __init__(self, data: dict):
        for k in list(data.keys()):
            if '.' in k:
                par_k, sub_k = k.split('.', 1)
                if par_k in data:
                    data[par_k][sub_k] = data.pop(k)
                else:
                    data[par_k] = {
                        sub_k: data.pop(k)
                    }

        super().__init__(data)


class DotDictReader(dict):
    def __init__(self, data: dict):
        super().__init__(data)

    def __getitem__(self, item):
        if isinstance(item, str):
            v = self
            for k in item.split('.'):
                v = dict.__getitem__(v, k)
        else:
            v = self[item]
        return v


class DataClass(object):

    def todict(self):
        data = {}
        for k, t in type(self).__dict__.items():
            if isinstance(t, property):
                data[k] = self[k]
        return data

    def __repr__(self):
        params = [f'{k}={repr(v)}' for k, v in self.todict().items()]
        return f'{type(self).__name__}({", ".join(params)})'

    __setitem__ = object.__setattr__
    __getitem__ = object.__getattribute__


class Descriptor(metaclass=abc.ABCMeta):
    def __init__(self, name: str, choices: typing.Sequence = None):
        self.name = name
        self.choices = choices
        self.val = None

    @abc.abstractmethod
    def set(self, instance, value):
        """设置字段值"""

    def __set__(self, instance, value):
        if self.choices:
            if not value:
                value = self.choices[0]
            elif value not in self.choices:
                raise ValueError(f'{self.name}: {value}, 只能是: {",".join(self.choices)}')
        self.val = self.set(instance, value)

    def __get__(self, instance, owner):
        return self.val


def set_string(value: str = None) -> str:
    return str(value or '').strip()


class StringDescriptor(Descriptor):
    def set(self, instance, value):
        return set_string(value)


def set_dict(value: dict = None) -> dict:
    return value or {}


class DictDescriptor(Descriptor):
    def set(self, instance, value):
        return set_dict(value)


def set_list(value: list = None) -> list:
    val = []
    for v in value or []:
        if v not in val:
            val.append(v)
    return val


class ListDescriptor(Descriptor):
    def set(self, instance, value):
        return set_list(value)
