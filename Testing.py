import unittest as test
import tracemalloc
import Enumeration

tracemalloc.start()


# Run all tests automatically
class TestEnum(test.TestCase):
    """
    Close GUI to run the test
    Resource warning is suppressed
    Functions don't have inputs, so it runs automatically and checks that outcome is not type=None
    Each function creates a file with the returned information
    """

    def test_version(self):
        self.assertIsNotNone(Enumeration.Enumeration.show_version)

    def test_usr(self):
        self.assertIsNotNone(Enumeration.Enumeration.show_user)

    def test_usr_list(self):
        self.assertIsNotNone(Enumeration.Enumeration.list_users)

    def test_processes(self):
        self.assertIsNotNone(Enumeration.Enumeration.show_processes)

    def test_port_scan(self):
        self.assertIsNotNone(Enumeration.Enumeration.port_scan)


if __name__ == '__main__':
    test.main()
