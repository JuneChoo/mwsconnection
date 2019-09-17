# _*_ coding:utf-8 _*_
__author__ = "JuneZhu"
__date__ = "2019/9/17 9:58"

import platform

__version__ = '2.0.0'
Version = __version__  # for backware compatibility

UserAgent = 'VanToP/%s Python/%s %s/%s' % (
    __version__,
    platform.python_version(),
    platform.system(),
    platform.release()
)