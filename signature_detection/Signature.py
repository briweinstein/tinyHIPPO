import abc

'''This abstract base class represents a single signature to be checked against packets in our IoT IDS'''


class Signature(abc.ABC):
    @abc.abstractmethod
    def __call__(self, packet: str):
        raise NotImplementedError
