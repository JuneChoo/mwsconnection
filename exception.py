# _*_ coding:utf-8 _*_
__author__ = "JuneZhu"
__date__ = "2019/9/17 17:14"

class PleaseRetryException(Exception):
    """
    Indicates a request should be retried.
    """
    def __init__(self, message, response=None):
        self.message = message
        self.response = response

    def __repr__(self):
        return 'PleaseRetryException("%s", %s)' % (
            self.message,
            self.response
        )