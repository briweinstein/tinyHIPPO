import unittest.mock as um


def assert_failed(data, privacy_obj, assert_funct):
    with um.patch("builtins.open", um.mock_open(read_data=data)):
        privacy_obj()
    try:
        assert_funct()
        return False
    except:
        return True
