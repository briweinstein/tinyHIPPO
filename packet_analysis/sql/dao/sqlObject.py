import abc


class sqlObject(abc.ABC):
    """
    Abstract class for data access objects
    """
    @abc.abstractmethod
    def csv(self) -> list:
        raise NotImplementedError

# See scapy layers package to understand what fields can be pulled for each protocol:
# https://scapy.readthedocs.io/en/latest/api/scapy.layers.html
