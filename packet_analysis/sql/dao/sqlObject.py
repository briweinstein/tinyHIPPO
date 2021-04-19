import abc


class sqlObject(abc.ABC):
    """
    Abstract class for data access objects. Packets are separated based on most specific layer.
    """

    @abc.abstractmethod
    def csv(self) -> list:
        """
        Creates a list of the arguments required for an INSERT statement
        :return: list
        """
        raise NotImplementedError

# See scapy layers package to understand what fields can be pulled for each protocol:
# https://scapy.readthedocs.io/en/latest/api/scapy.layers.html
