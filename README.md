BDNetDisk API
====================================
fork from https://github.com/ly0/baidupcsapi

Explainations
-----------
The author seems to mistake pcs as netdisk,
which makes it as baidupcsapi, but actually baidupanapi.

Updates later
-----------

* we can't see wenxintishi.avi any more.
* login with RSA encryption, details refer to `_get_pubkey` and `_login` PCS(api.py).
* download_url in PCS can access direct download links<br>support brust, pass str or list in.
* specify `captcah_func` in  `__init__`() of BaseClass, the first parameter pass jpeg data in.


References
======================

As bd pcs api is no more accessible for us, now we can use api of bd itself
*   https://github.com/mozillazg/baidu-pcs-python-sdk/wiki/%E5%A6%82%E4%BD%95%E8%8E%B7%E5%8F%96-Access-Token-%E5%92%8C-Refresh-Token%EF%BC%9F

* http://baidupcsapi.readthedocs.org/

API fuse(tested in ubuntu 12.04)
* http://github.com/ly0/baidu-fuse

Web edition(tested in ubuntu 14.04)
* https://github.com/ly0/web.baidupan

* Documents: http://ly0.github.io/baidupcsapi
* Free software: MIT license
* PyPI: https://pypi.python.org/pypi/baidupcsapi
* Python version: 2.7
* require: requests>=2.0.0, requests_toolbelt>=0.1.2
* delivered as baidupcsapi on pypi


Installation
------------
```shell
$ pip install baidupcsapi
```
if you encounter some depencies problems, just fix them.

simple tests
-----------
```python
>>> from baidupcsapi import PCS
>>> pcs = PCS('username','password')
>>> print pcs.quota().content
>>> print pcs.list_files('/').content
```
download
-----------

```python
>>> headers = {'Range': 'bytes=0-99'}
>>> pcs = PCS('username','password')
>>> pcs.download('/test_sdk/test.txt', headers=headers)
```

upload
-------

A demo will be published in the later future.
-> slice file
-> md5sum
-> upload_tmpfile
-> upload_superfile
files are stored as pieces permanently.
upload functions have callbacks.


concatenate
------

used to concatenate file sections.

1.txt + 2.txt => 3.txt
```python
pcs = PCS('username','password')
print 'chunk1'
ret = pcs.upload_tmpfile(open('1.txt','rb'))
md51 = json.loads(ret.content)['md5']
print 'chunk2'
ret = pcs.upload_tmpfile(open('2.txt','rb'))
md52 = json.loads(ret.content)['md5']
print 'merge'
ret = pcs.upload_superfile('/3.txt',[md51,md52])
print ret.content
```


Upload ProcessBar
------

callback pararmeters:
	size: number of file bytes
	progress: processed size

```python
	import progressbar
	from baidupcsapi import PCS
	class ProgressBar():
	    def __init__(self):
	        self.first_call = True
	    def __call__(self, *args, **kwargs):
	        if self.first_call:
	            self.widgets = [progressbar.Percentage(), ' ', progressbar.Bar(marker=progressbar.RotatingMarker('>')),
	                            ' ', progressbar.ETA()]
	            self.pbar = progressbar.ProgressBar(widgets=self.widgets, maxval=kwargs['size']).start()
	            self.first_call = False

	        if kwargs['size'] <= kwargs['progress']:
	            self.pbar.finish()
	        else:
	            self.pbar.update(kwargs['progress'])


	pcs = PCS('username','password') # avoid hardcoding
	test_file = open('bigfile.pdf','rb').read()
	ret = pcs.upload('/',test_file,'bigfile.pdf',callback=ProgressBar())
```
