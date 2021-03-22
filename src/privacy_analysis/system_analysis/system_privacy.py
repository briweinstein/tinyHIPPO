#! /usr/bin/env python3
import abc


class SystemPrivacy(abc.ABC):
    """
    This abstract base class represents a single privacy rule to be checked against the system in our IoT Privacy Protection System
    """

    @property
    def msg(self):
        return type(self).__name__

    @abc.abstractmethod
    def __call__(self) -> None:
        raise NotImplementedError
