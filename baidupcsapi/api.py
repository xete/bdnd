#!/usr/bin/env python
# -*- coding: utf-8 -*-

from functools import wraps
import re
import time
import json
import os
import logging
import pickle
import string
import random
import base64
from hashlib import sha1, md5
from urllib import urlencode, quote
from zlib import crc32
from requests_toolbelt import MultipartEncoder
import requests
# maybe you can solve the ssl ca here
requests.packages.urllib3.disable_warnings()
import rsa
import urllib


"""
logging.basicConfig(level=logging.DEBUG,
                format='%(asctime)s %(filename)s[line:%(lineno)d] %(levelname)s %(message)s',
                datefmt='%a, %d %b %Y %H:%M:%S')
"""

BAIDUPAN_SERVER = 'pan.baidu.com'
BAIDUPCS_SERVER = 'pcs.baidu.com'
BAIDUPAN_HEADERS = {"Referer": "http://pan.baidu.com/disk/home",
                    "User-Agent": "netdisk;4.6.2.0;PC;PC-Windows;10.0.10240;WindowsBaiduYunGuanJia"}

# https://pcs.baidu.com/rest/2.0/pcs/manage?method=listhost -> baidu cdn
# uses CDN_DOMAIN/monitor.jpg to test speed for each CDN
api_template = 'http://%s/api/{0}' % BAIDUPAN_SERVER


class LoginFailed(Exception):

    """
	login failure caused by account
	excluding login timeout.
    """
    pass

# experimental


class CancelledError(Exception):

    """
	occur when user cancel upload
    """

    def __init__(self, msg):
        self.msg = msg
        Exception.__init__(self, msg)

    def __str__(self):
        return self.msg

    __repr__ = __str__


class BufferReader(MultipartEncoder):

    """
	multipart-formdatai to Proxy class in the form of stream
    """

    def __init__(self, fields, boundary=None, callback=None, cb_args=(), cb_kwargs={}):
        self._callback = callback
        self._progress = 0
        self._cb_args = cb_args
        self._cb_kwargs = cb_kwargs
        super(BufferReader, self).__init__(fields, boundary)

    def read(self, size=None):
        chunk = super(BufferReader, self).read(size)
        self._progress += int(len(chunk))
        self._cb_kwargs.update({
            'size': self._len,
            'progress': self._progress
        })
        if self._callback:
            try:
                self._callback(*self._cb_args, **self._cb_kwargs)
            except:  # catches exception from the callback
                raise CancelledError('The upload was cancelled.')
        return chunk


def check_login(func):
    """
	check user login status(pcs checking method)
    """
    @wraps(func)
    def wrapper(*args, **kwargs):
        ret = func(*args, **kwargs)
        if type(ret) == requests.Response:
            try:
                foo = json.loads(ret.content)
                if foo.has_key('errno') and foo['errno'] == -6:
                    logging.debug(
                        'Offline, deleting cookies file then relogin.')
                    path = '.{0}.cookies'.format(args[0].username)
                    if os.path.exists(path):
                        os.remove(path)
                    args[0]._initiate()
            except:
                pass
        return ret
    return wrapper


class BaseClass(object):

    """
	provide basic pcs methods
    """

    def __init__(self, username, password, api_template=api_template, captcha_func=None):
        self.session = requests.session()
        self.api_template = api_template
        self.username = username
        self.password = password
        self.user = {}
        self.progress_func = None
        if captcha_func:
            self.captcha_func = captcha_func
        else:
            self.captcha_func = self.show_captcha
        logging.debug('setting pcs server')
        self.set_pcs_server(self.get_fastest_pcs_server())
        self._initiate()

    def get_fastest_pcs_server_test(self):
        """
		return the address of the fastest pcs server
		in str
        """
        ret = requests.get('https://pcs.baidu.com/rest/2.0/pcs/manage?method=listhost').content
        serverlist = [server['host'] for server in json.loads(ret)['list']]
        url_pattern = 'http://{0}/monitor.jpg'
        time_record = []
        for server in serverlist:
            start = time.time() * 1000
            requests.get(url_pattern.format(server))
            end = time.time() * 1000
            time_record.append((end - start, server))
            logging.info('TEST %s %s ms' % (server, int(end - start)))
        return min(time_record)[1]

    def get_fastest_pcs_server(self):
		"""
		return the address of the fastest pcs server from bd
        """
        url = 'http://pcs.baidu.com/rest/2.0/pcs/file?app_id=250528&method=locateupload'
        ret = requests.get(url).content
        foo = json.loads(ret)
        return foo['host']

    def set_pcs_server(self, server):
        """
		manually set bd pcs server
		server: address or domain
			(NOTE)no leading 'http://' and tailing '/'
        """
        global BAIDUPCS_SERVER
        BAIDUPCS_SERVER = server

    def _remove_empty_items(self, data):
        for k, v in data.copy().items():
            if v is None:
                data.pop(k)

    def _initiate(self):
        if not self._load_cookies():
            self.session.get('http://www.baidu.com')
            self.user['token'] = self._get_token()
            self._login()
        else:
            self.user['token'] = self._get_token()

    def _save_cookies(self):
        cookies_file = '.{0}.cookies'.format(self.username)
        with open(cookies_file, 'w') as f:
            pickle.dump(
                requests.utils.dict_from_cookiejar(self.session.cookies), f)

    def _load_cookies(self):
        cookies_file = '.{0}.cookies'.format(self.username)
        logging.debug('cookies file:' + cookies_file)
        if os.path.exists(cookies_file):
            logging.debug('%s cookies file has already existed.' %
                          self.username)
            with open(cookies_file) as cookies_file:
                cookies = requests.utils.cookiejar_from_dict(
                    pickle.load(cookies_file))
                logging.debug(str(cookies))
                self.session.cookies = cookies
                self.user['BDUSS'] = self.session.cookies['BDUSS']
                return True
        else:
            return False

    def _get_token(self):
        # Token
		url = 'https://passport.baidu.com/v2/api/?getapi&tpl=mn&apiver=v3&class=login&tt=%s&logintype=dialogLogin&callback=0' 
        ret = self.session.get(url% int(time.time())).text.replace('\'', '\"')
        foo = json.loads(ret)
        logging.info('token %s' % foo['data']['token'])
        return foo['data']['token']

    def _get_captcha(self, code_string):
        # Captcha
        if code_string:
            verify_code = self.captcha_func("https://passport.baidu.com/cgi-bin/genimage?" + code_string)
        else:
            verify_code = ""

        return verify_code

    def show_captcha(self, url_verify_code):
        print(url_verify_code)
        verify_code = raw_input('open url aboved with your web browser, then input verify code > ')

        return verify_code

    def _get_publickey(self):
        url = 'https://passport.baidu.com/v2/getpublickey?token=' + \
            self.user['token']
        content = self.session.get(url).content
        jdata = json.loads(content.replace('\'','"'))
        return (jdata['pubkey'], jdata['key'])

    def _login(self):
        # Login
        #code_string, captcha = self._get_captcha()
        captcha = ''
        code_string = ''
        pubkey, rsakey = self._get_publickey()
        key = rsa.PublicKey.load_pkcs1_openssl_pem(pubkey)
        password_rsaed = base64.b64encode(rsa.encrypt(self.password, key))
        while True:
            login_data = {'staticpage': 'http://www.baidu.com/cache/user/html/v3Jump.html',
                          'charset': 'UTF-8',
                          'token': self.user['token'],
                          'tpl': 'pp',
                          'subpro': '',
                          'apiver': 'v3',
                          'tt': str(int(time.time())),
                          'codestring': code_string,
                          'isPhone': 'false',
                          'safeflg': '0',
                          'u': 'https://passport.baidu.com/',
                          'quick_user': '0',
                          'logLoginType': 'pc_loginBasic',
                          'loginmerge': 'true',
                          'logintype': 'basicLogin',
                          'username': self.username,
                          'password': password_rsaed,
                          'verifycode': captcha,
                          'mem_pass': 'on',
                          'rsakey': str(rsakey),
                          'crypttype': 12,
                          'ppui_logintime': '50918',
                          'callback': 'parent.bd__pcbs__oa36qm'}
            result = self.session.post(
                'https://passport.baidu.com/v2/api/?login', data=login_data)

			# whether need captcha
            if 'err_no=257' in result.content or 'err_no=6' in result.content:
                code_string = re.findall('codeString=(.*?)&', result.content)[0]
                logging.debug('need captcha, codeString=' + code_string)
                captcha = self._get_captcha(code_string)
                continue

            break

        # check exception
        self._check_account_exception(result.content)

        if not result.ok:
            raise LoginFailed('Logging failed.')
        logging.info('COOKIES' + str(self.session.cookies))
        try:
            self.user['BDUSS'] = self.session.cookies['BDUSS']
        except:
            raise LoginFailed('Logging failed.')
        logging.info('user %s Logged in BDUSS: %s' %
                     (self.username, self.user['BDUSS']))
        self._save_cookies()

    def _check_account_exception(self, content):
        err_id = re.findall('err_no=([\d]+)', content)[0]

        if err_id == '0':
            return
        error_message = {
            '-1':'system error, try later',
            '1':'account format error',
            '3':'captcha does not exist or out-dated',
            '4': 'account and passwd not match',
            '5': 'try the pop-up window or re-login',
            '6':'captcha no match',
            '16': 'account login not permitted',
            '257': 'need to input captcha character',
            '100005': 'system error, try later',
            '120016': 'unknow error: 120016',
            '120019': 'logining too frequent, go to passport.baidu.com for unfreezing',
            '120021': 'try the pop-up window or re-login',
            '500010': 'logining too frequent, try 24 hours later',
            '400031': 'account exception, login on web first',
            '401007': 'your phone number has linked with other accounts'}
        try:
            msg = error_message[err_id]
        except:
            msg = 'unknown err_id=' + err_id
        raise LoginFailed(msg)

    def _params_utf8(self, params):
        for k, v in params.items():
            if isinstance(v, unicode):
                params[k] = v.encode('utf-8')

    @check_login
    def _request(self, uri, method=None, url=None, extra_params=None,
                 data=None, files=None, callback=None, **kwargs):
        params = {
            'method': method,
            'app_id': "250528",
            'BDUSS': self.user['BDUSS'],
            't': str(int(time.time())),
            'bdstoken': self.user['token']
        }
        if extra_params:
            params.update(extra_params)
            self._remove_empty_items(params)

        headers = dict(BAIDUPAN_HEADERS)
        if 'headers' in kwargs:
            headers.update(kwargs['headers'])
            kwargs.pop('headers')

        self._params_utf8(params)
        if not url:
            url = self.api_template.format(uri)
        if data or files:

            if '?' in url:
                api = "%s&%s" % (url, urlencode(params))
            else:
                api = '%s?%s' % (url, urlencode(params))

            # print params
            if data:
                self._remove_empty_items(data)
                response = self.session.post(api, data=data, verify=False,
                                             headers=headers, **kwargs)
            else:
                self._remove_empty_items(files)

                body = BufferReader(files, callback=callback)
                headers.update({
                    "Content-Type": body.content_type
                }
                )

                response = self.session.post(
                    api, data=body, verify=False, headers=headers, **kwargs)
        else:
            api = url
            if uri == 'filemanager' or uri == 'rapidupload' or uri == 'filemetas' or uri == 'precreate':
                response = self.session.post(
                    api, params=params, verify=False, headers=headers, **kwargs)
            else:
                response = self.session.get(
                    api, params=params, verify=False, headers=headers, **kwargs)
        return response


class PCS(BaseClass):

    def __init__(self,  username, password, captcha_callback=None):
        """
		username: str
		password: str
        captcha_callback: callback for captcha_processing, jpeg will be passed in
        """
        super(PCS, self).__init__(username, password, api_template, captcha_func=captcha_callback)

    def __err_handler(self, act, errno, callback=None, args=(), kwargs={}):
        """
		error handler for certain possible errors
		act: action that go wrong(download)
		errno: error number, combine with act
		callback: call when return, None when null
		args: parameters to pass in to callback(tuple)
		kwargs: parameters dictionary
		
        """
        errno = int(errno)

        def err_handler_download():
            if errno == 112:
				# page not available, please reload
                url = 'http://pan.baidu.com/disk/home'
                self.session.get(url)

            return

        def err_handler_upload():
            return

        def err_handler_generic():
            return

        _act = {
			'download': err_handler_download,
			'upload': err_handler_upload,
			'generic': err_handler_generic
                }

        if act not in _act:
            raise Exception('undefined error, no way to go')

        if callback:
            return callback(*args, **kwargs)
        return None

    def quota(self, **kwargs):
        """
		get response information
			{"errno":0,"total":bytes_allocated,"used":bytes_used,"request_id":request_id}
        """
        return self._request('quota', **kwargs)

    def upload(self, dir, file_handler, filename, ondup="newcopy", callback=None, **kwargs):
        """
		upload single file(less than 2GB, those beyond this limit should be sliced)
		dir: file path on remote server, begins with '/'
		     * path only, no filename included
			 * lenght < 1000
			 * \ ? | " > < : * NOT allowed
			 * not leading by or following by . 
			 * \r \n \t \SPC \0 \x0B NOT allowed
        filename
        file_handler:
		     fd -> open('foobar', 'rb')
        callback: upload callback, with paramters size and progress
        ondup:
		     * 'overwrite'
			 * 'newcopy': copy the existing as filename_date.suffix
        return: requests.Response object
		    {
		    "path":file path on server,
			"size":filesize,
			"ctime":create time,
			"mtime":modified time,
			"md5":md5 valuel,
			"fs_id":file id on server,
			"isdir":direcotry,
			"request_id":request id
			}
        """

        params = {
            'dir': dir,
            'ondup': ondup,
            'filename': filename
        }

        tmp_filename = ''.join(random.sample(string.ascii_letters, 10))
        files = {'file': (tmp_filename, file_handler)}

        url = 'https://{0}/rest/2.0/pcs/file'.format(BAIDUPCS_SERVER)
        return self._request('file', 'upload', url=url, extra_params=params,
                             files=files, callback=callback, **kwargs)

    def upload_tmpfile(self, file_handler, callback=None, **kwargs):
        """
		slicing upload
			* upload files larger than 2GB
			* continuous uploading(set uploading points)
		parameters similar to self.upload()
        return: requests.Response
		    {
			"md5":md5 value for this section, for later concatencating,
		    "request_id":request id
			}
        """

        params = {
            'type': 'tmpfile'
        }
        files = {'file': (str(int(time.time())), file_handler)}
        url = 'https://{0}/rest/2.0/pcs/file'.format(BAIDUPCS_SERVER)
        return self._request('file', 'upload', url=url, extra_params=params, callback=callback,
                             files=files, **kwargs)

    def upload_superfile(self, remote_path, block_list, ondup="newcopy", **kwargs):
        """
		concatencating files
		remote_path: file path + filename
		    limits similar to self.upload()
        block_list: md5 list(2-1024)
        return: request.Response object
			object similar to self.upload()
        """

        params = {
            'path': remote_path,
            'ondup': ondup
        }
        data = {
            'param': json.dumps({'block_list': block_list}),
        }
        url = 'https://{0}/rest/2.0/pcs/file'.format(BAIDUPCS_SERVER)
        return self._request('file', 'createsuperfile', url=url, extra_params=params,
                             data=data, **kwargs)

    def get_sign(self):
        # refered:
        #	https://github.com/PeterDing/iScript/blob/master/pan.baidu.com.py
        url = 'http://pan.baidu.com/disk/home'
        r = self.session.get(url)
        html = r.content
        sign1 = re.search(r'"sign1":"([A-Za-z0-9]+)"', html).group(1)
        sign3 = re.search(r'"sign3":"([A-Za-z0-9]+)"', html).group(1)
        timestamp = re.search(r'"timestamp":([0-9]+)[^0-9]', html).group(1)

        def sign2(j, r):
            a = []
            p = []
            o = ''
            v = len(j)

            for q in xrange(256):
                a.append(ord(j[q % v]))
                p.append(q)

            u = 0
            for q in xrange(256):
                u = (u + p[q] + a[q]) % 256
                t = p[q]
                p[q] = p[u]
                p[u] = t

            i = 0
            u = 0
            for q in xrange(len(r)):
                i = (i + 1) % 256
                u = (u + p[i]) % 256
                t = p[i]
                p[i] = p[u]
                p[u] = t
                k = p[((p[i] + p[u]) % 256)]
                o += chr(ord(r[q]) ^ k)

            return base64.b64encode(o)

        self.dsign = sign2(sign3, sign1)
        self.timestamp = timestamp

    def _locatedownload(self, remote_path, **kwargs):
        """
		bd guanjia method
        """
        params = {
            'path': remote_path
        }
        url = 'https://{0}/rest/2.0/pcs/file'.format(BAIDUPCS_SERVER)
        return self._request('file', 'locatedownload', url=url,
                             extra_params=params, **kwargs)

    def _yunguanjia_format(self, remote_path, **kwargs):
        ret = self._locatedownload(remote_path, **kwargs).content
        data = json.loads(ret)
        return 'http://' + data['host'] + data['path']

    def download_url(self, remote_path, **kwargs):
        """
		return usable DIRECT link
        """

        def get_url(dlink):
            return self.session.get(dlink,
                                    headers=BAIDUPAN_HEADERS,
                                    stream=True).url

        if not hasattr(self, 'dsign'):
            self.get_sign()

        if isinstance(remote_path, str) or isinstance(remote_path, unicode):
            remote_path = [remote_path]

        file_list = []
        jdata = json.loads(self.meta(remote_path).content)
        if jdata['errno'] != 0:
            jdata = self.__err_handler('generic', jdata['errno'],
                                       self.meta,
                                       args=(remote_path,)
                                       )
        logging.debug('[*]' + str(jdata))
        for i, entry in enumerate(jdata['info']):
            url = entry['dlink']
            foo = get_url(url)
            if 'wenxintishi' in foo:
                file_list.append(self._yunguanjia_format(remote_path[i]))
            else:
                file_list.append(get_url(entry['dlink']))

        return file_list

    # Deprecated
    # using download_url to get real download url
    def download(self, remote_path, **kwargs):
        """
		download single file
		** refer to HTTP protocal Range definition
		>>> headers = {'Range': 'bytes=0-99'}
		>>> pcs = PCS('username','password')
		>>> pcs.download('/test_sdk/test.txt', headers=headers)
        """

        params = {
            'path': remote_path,
        }
        url = 'https://{0}/rest/2.0/pcs/file'.format(BAIDUPCS_SERVER)
        return self._request('file', 'download', url=url,
                             extra_params=params, **kwargs)


    def get_streaming(self, path, stype="M3U8_AUTO_480", **kwargs):
        """
		get m3u8 list of videos
        path: video file path
		stype:
		    * M3U8_AUTO_240(unstable)
		    * M3U8_AUTO_480(dfl)
		    * M3U8_AUTO_720
        return: str playlist info
        """

        params = {
            'path': path,
            'type': stype
        }
        url = 'https://{0}/rest/2.0/pcs/file'.format(BAIDUPCS_SERVER)
        while True:
            ret = self._request('file', 'streaming', url=url, extra_params=params, **kwargs)
            if not ret.ok:
                logging.debug('get_streaming ret_status_code %s' % ret.status_code)
                jdata = json.loads(ret.content)
                if jdata['error_code'] == 31345:
                    # try again
                    continue
                elif jdata['error_code'] == 31066:
                    # file non exist 
                    return 31066
                elif jdata['error_code'] == 31304:
                    # no supported type 
                    return 31304
                elif jdata['error_code'] == 31023:
                    # params error
                    return 31023
            return ret.content
 
    def mkdir(self, remote_path, **kwargs):
        """
        remote_path: path leading with '/'
        return: Response
		    {
			"fs_id":file id,
			"path":file path,
			"ctime":create,
			"mtime":modify,
			"status":0,
			"isdir":1,
			"errno":0,
			"name":file path
			}
        """

        data = {
            'path': remote_path,
            'isdir': "1",
            "size": "",
            "block_list": "[]"
        }
		# post ??
        return self._request('create', 'post', data=data, **kwargs)

    def list_files(self, remote_path, by="name", order="desc",
                   limit=None, **kwargs):
        """
		similar to ls
        by: order by key
		    * time
		    * name
		    * size
        order:
		    * asc +
			* desc -
        limit: return items in list [start, end)
        return: requests.Response
			{
			"errno":0,
			"list":[
				{
				"fs_id":file id,
				"path":path,
				"server_filename":filename,
				"size":file size,
				"server_mtime":modify,
				"server_ctime":create,
				"local_mtime":local modify,
				"local_ctime":local create,
				"isdir":diretory,
				"category":type,
				"md5":md5 vlaue}
				...
		     ],
			"request_id": request id
			}

        """
        if order == "desc":
            desc = "1"
        else:
            desc = "0"

        params = {
            'dir': remote_path,
            'order': by,
            'desc': desc
        }
        return self._request('list', 'list', extra_params=params, **kwargs)

    def move(self, path_list, dest, **kwargs):
        """
        path_list: source list
        dest: str

        """
        def __path(path):
            if path.endswith('/'):
                return path.split('/')[-2]
            else:
                return os.path.basename(path)
        params = {
            'opera': 'move'
        }
        data = {
            'filelist': json.dumps([{
                "path": path,
                "dest": dest,
                "newname": __path(path)} for path in path_list]),
        }
        url = 'http://{0}/api/filemanager'.format(BAIDUPAN_SERVER)
        return self._request('filemanager', 'move', url=url, data=data, extra_params=params, **kwargs)

    def rename(self, rename_pair_list, **kwargs):
        """
        rename_pair_list:
			* list of pairs of (origin, renamed)
        """
        foo = []
        for path, newname in rename_pair_list:
            foo.append({'path': path,
                        'newname': newname
                        })

        data = {'filelist': json.dumps(foo)}
        params = {
            'opera': 'rename'
        }

        url = 'http://{0}/api/filemanager'.format(BAIDUPAN_SERVER)
        print 'request url: ', url
        logging.debug('rename ' + str(data) + 'URL:' + url)
        return self._request('filemanager', 'rename', url=url, data=data, extra_params=params, **kwargs)

    def copy(self, path_list, dest, **kwargs):
        """
        path_list: list
        dest: str
        """
        def __path(path):
            if path.endswith('/'):
                return path.split('/')[-2]
            else:
                return os.path.basename(path)
        params = {
            'opera': 'copy'
        }
        data = {
            'filelist': json.dumps([{
                "path": path,
                "dest": dest,
                "newname": __path(path)} for path in path_list]),
        }
        url = 'http://{0}/api/filemanager'.format(BAIDUPAN_SERVER)
        return self._request('filemanager', 'move', url=url, data=data, extra_params=params, **kwargs)

    def delete(self, path_list, **kwargs):
        """
        path_list: list
        """
        data = {
            'filelist': json.dumps([path for path in path_list])
        }
        url = 'http://{0}/api/filemanager?opera=delete'.format(BAIDUPAN_SERVER)
        return self._request('filemanager', 'delete', url=url, data=data, **kwargs)

    def share(self, file_ids, pwd=None, **kwargs):
        """
		create a shared link
        file_ids: list of file id
        path_list: list
        pwd: share password, str
        return: requests.Response
			{
			"errno": 0,
			"request_id": request id,
			"shareid": share id,
			"link": share link,
			"shorturl": short url,
			"ctime": create time
			"premis": false
			}
        """
        if pwd:
            data = {
                'fid_list': json.dumps([int(fid) for fid in file_ids]),
                'pwd': pwd,
                'schannel': 4,
                'channel_list': json.dumps([])
            }
        else:
            data = {
                'fid_list': json.dumps([int(fid) for fid in file_ids]),
                'schannel': 0,
                'channel_list': json.dumps([])
            }
        url = 'http://pan.baidu.com/share/set'
        return self._request('share/set', '', url=url, data=data, **kwargs)

    def list_streams(self, file_type, start=0, limit=1000, order='time', desc='1',
                     filter_path=None, **kwargs):
        """
        file_type:
		    * video
			* audio
			* image
			* doc
			* other
			* exe
			* torrent
        start: return items begining index
        limit: return items number, dfl 1000 
        filter_path: path filter 
        return: same as self.list_files()
        """
        if file_type == 'doc':
            file_type = '4'
        elif file_type == 'video':
            file_type = '1'
        elif file_type == 'image':
            file_type = '3'
        elif file_type == 'torrent':
            file_type = '7'
        elif file_type == 'other':
            file_type = '6'
        elif file_type == 'audio':
            file_type = '2'
        elif file_type == 'exe':
            file_type = '5'

        params = {
            'category': file_type,
            'pri': '-1',
            'start': start,
            'num': limit,
            'order': order,
            'desc': desc,
            'filter_path': filter_path,
        }
        url = 'http://pan.baidu.com/api/categorylist'
        return self._request('categorylist', 'list', url=url, extra_params=params,
                             **kwargs)

    def add_download_task(self, source_url, remote_path, selected_idx=(), **kwargs):
        """
		offline download
        """
        if source_url.startswith('magnet:?'):
            print('Magnet: "%s"' % source_url)
            return self.add_magnet_task(source_url, remote_path, selected_idx, **kwargs)
        elif source_url.endswith('.torrent'):
            print('BitTorrent: "%s"' % source_url)
            return self.add_torrent_task(source_url, remote_path, selected_idx, **kwargs)
        else:
            print('Others: "%s"' % source_url)
            data = {
                'method': 'add_task',
                'source_url': source_url,
                'save_path': remote_path,
            }
            url = 'http://{0}/rest/2.0/services/cloud_dl'.format(BAIDUPAN_SERVER)
            return self._request('services/cloud_dl', 'add_task', url=url,
                                 data=data, **kwargs)

    def add_torrent_task(self, torrent_path, save_path='/', selected_idx=(), **kwargs):
        """
		add local BT task
        torrent_path: local torrent path
        save_path: remote save path
        selected_idx: file index to download, null means all
        return: requests.Response
			{
			"task_id":task id,
			"rapid_download":whether rapid download,
			"request_id":request id
			}
        """

        # upload torrent 
        torrent_handler = open(torrent_path, 'rb')
        basename = os.path.basename(torrent_path)

        # clean duplicated file 
        self.delete(['/' + basename])

        response = self.upload('/', torrent_handler, basename).json()
        remote_path = response['path']
        logging.debug('REMOTE PATH:' + remote_path)

        # get torrent info 
        response = self._get_torrent_info(remote_path).json()
        if response.get('error_code'):
            print(response.get('error_code'))
            return
        if not response['torrent_info']['file_info']:
            return

        if isinstance(selected_idx, (tuple, list, set)):
            if len(selected_idx) > 0:
                selected_idx = ','.join(map(str, selected_idx))
            else:
                selected_idx = ','.join(map(str, range(1, len(response['torrent_info']['file_info']) + 1)))
        else:
            selected_idx = ''

        data = {
            'file_sha1': response['torrent_info']['sha1'],
            'save_path': save_path,
            'selected_idx': selected_idx,
            'task_from': '1',
            'source_path': remote_path,
            'type': '2'  # 2 is torrent file
        }
        url = 'http://{0}/rest/2.0/services/cloud_dl'.format(BAIDUPAN_SERVER)
        return self._request('create', 'add_task', url=url, data=data, **kwargs)

    def _get_torrent_info(self, torrent_path):
        data = {
            'source_path': torrent_path,
            'type': '2'  # 2 is torrent
        }
        url = 'http://{0}/rest/2.0/services/cloud_dl'.format(BAIDUPAN_SERVER)

        return self._request('cloud_dl', 'query_sinfo', url=url, data=data, timeout=30)

    def add_magnet_task(self, magnet, remote_path, selected_idx=(), **kwargs):
        response = self._get_magnet_info(magnet).json()
        if response.get('error_code'):
            print(response.get('error_code'))
            return
        if not response['magnet_info']:
            return

        if isinstance(selected_idx, (tuple, list, set)):
            if len(selected_idx) > 0:
                selected_idx = ','.join(map(str, selected_idx))
            else:
                selected_idx = ','.join(map(str, range(1, len(response['magnet_info']) + 1)))
        else:
            selected_idx = ''

        data = {
            'source_url': magnet,
            'save_path': remote_path,
            'selected_idx': selected_idx,
            'task_from': '1',
            'type': '4'  # 4 is magnet
        }
        url = 'http://{0}/rest/2.0/services/cloud_dl'.format(BAIDUPAN_SERVER)

        return self._request('create', 'add_task', url=url, data=data, timeout=30)

    def _get_magnet_info(self, magnet):
        data = {
            'source_url': magnet,
            'save_path': '/',
            'type': '4'  # 4 is magnet
        }
        url = 'http://{0}/rest/2.0/services/cloud_dl'.format(BAIDUPAN_SERVER)

        return self._request('cloud_dl', 'query_magnetinfo', url=url, data=data, timeout=30)

    def query_download_tasks(self, task_ids, operate_type=1, **kwargs):
        """
		query task info by task id
        task_ids: list or tuple
        operate_type:
			* 0: task info
			* 1: progress info(dfl)
        return: requests.Response
			{
			"task_info": {
			    "70970481": {
					"status":"0",
					"file_size":"122328178",
					"finished_size":"122328178",
					"create_time":"1391620757",
					"start_time":"1391620757",
					"finish_time":"1391620757",
					"save_path":"\/",
					"source_url":"\/saki-nation04gbcn.torrent",
					"task_name":"[KTXP][Saki-National][04][GB_CN][720p]",
					"od_type":"2",
					"file_list":[
					{
						"file_name":"[KTXP][Saki-National][04][GB_CN][720p].mp4",
						"file_size":"122328178"
					}
					],
					"result":0
				}
			},
			"request_id":861570268
			}
        """

        params = {
            'task_ids': ','.join(map(str, task_ids)),
            'op_type': operate_type,
        }
        url = 'http://{0}/rest/2.0/services/cloud_dl'.format(BAIDUPAN_SERVER)
        return self._request('services/cloud_dl', 'query_task', url=url,
                             extra_params=params, **kwargs)

    def download_tasks_number(self):
        """
        return: int
        """
        ret = self.list_download_tasks().content
        foo = json.loads(ret)
        return foo['total']

    def list_download_tasks(self, need_task_info="1", asc="0", start=0, create_time=None, limit=1000, status="255", source_url=None, remote_path=None, **kwargs):
        """
        need_task_info:
			* 1: yes(dfl)
        start: 0 dfl
        limit: 10 dfl
        asc:
            * 0: -(dfl)
	    status:
		   0: success
		   1: in process
		   2: system error
		   3: resource non exist
		   4: download timeout
		   5: exist but fail
		   6: out of storage
		   7: data already exist
		   8: task cancelled
        remote_path: file path, '' dfl
        expires: request expires
        return: Response
			{
			"task_info": [
				{
				"task_id": task id,
				"od_type": "2",
				"source_url": origin url, or bt path on server,
				"save_path": save path,
				"rate_limit": 0(dfl) no limitations,
				"timeout": "0",
				"callback": "",
				"status": task status, 
				"create_time": create time,
				"task_name": task name, 
				},...
			],
			"total": total number,
			"request_id": request id 
			}
        """

        params = {
            'start': start,
            'limit': limit,
            'status': status,
            'need_task_info': need_task_info,
            'asc': asc,
            'source_url': source_url,
            'remote_path': remote_path,
            'create_time': create_time

        }
        url = 'http://{0}/rest/2.0/services/cloud_dl'.format(BAIDUPAN_SERVER)
        return self._request('services/cloud_dl', 'list_task', url=url, extra_params=params, **kwargs)

    def cancel_download_task(self, task_id, expires=None, **kwargs):
        """
        return: requests.Response
        """

        data = {
            'expires': expires,
            'task_id': task_id,
        }
        url = 'http://{0}/rest/2.0/services/cloud_dl'.format(BAIDUPAN_SERVER)
        return self._request('services/cloud_dl', 'cancel_task', url=url,
                             data=data, **kwargs)

    def list_recycle_bin(self, order="time", desc="1", start=0, limit=1000, page=1, **kwargs):
        """
        start: 0(dfl)
        limit: 1000(dfl) 
        return: requests.Response
            same as self.list_files()
        """

        params = {
            'start': start,
            'num': limit,
            'dir': '/',
            'order': order,
            'desc': desc
        }
        url = 'http://{0}/api/recycle/list'.format(BAIDUPAN_SERVER)
        return self._request('recycle', 'list', url=url, extra_params=params, **kwargs)

    def restore_recycle_bin(self, fs_ids, **kwargs):
        """
        fs_ids: unizue id list of file(list or tuple)
        return: requests.Response
        """

        data = {
            'filelist': json.dumps([fs_id for fs_id in fs_ids])
        }
        url = 'http://{0}/api/recycle/restore'.format(BAIDUPAN_SERVER)
        return self._request('recycle', 'restore', data=data, **kwargs)

    def clean_recycle_bin(self, **kwargs):
        """
        return: requests.Response
        """

        url = 'http://{0}/api/recycle/clear'.format(BAIDUPAN_SERVER)
        return self._request('recycle', 'clear', url=url, **kwargs)

    def rapidupload(self, file_handler, path, **kwargs):
        """
        return: requests.Response
			* file exists, no need to upload
			{
				"path" : "/path/to/existing/file",
				"size" : file size,
				"ctime" : 1234567890,
				"mtime" : 1234567890,
				"md5" : "cb123afcc12453543ef",
				"fs_id" : 12345,
				"isdir" : 0,
				"request_id" : 12314124
			}
			* need to be uploaded
			{"errno":404,"info":[],"request_id":XXX}
			* file size < 256kb (slice-md5 == content-md5)
			{"errno":2,"info":[],"request_id":XXX}
			* remote file exist
			{"errno":-8,"info":[],"request_id":XXX}

        """
        file_handler.seek(0, 2)
        _BLOCK_SIZE = 2 ** 20
        content_length = file_handler.tell()
        file_handler.seek(0)

        # check the leading 256kb
        first_256bytes = file_handler.read(256 * 1024)
        slice_md5 = md5(first_256bytes).hexdigest()

        content_crc32 = crc32(first_256bytes).conjugate()
        content_md5 = md5(first_256bytes)

        while True:
            block = file_handler.read(_BLOCK_SIZE)
            if not block:
                break
            # update crc32 and md5 checksum
            content_crc32 = crc32(block, content_crc32).conjugate()
            content_md5.update(block)

        data = {'path': path,
                'content-length': content_length,
                'content-md5': content_md5.hexdigest(),
                'slice-md5': slice_md5,
                'content-crc32': '%d' % (content_crc32.conjugate() & 0xFFFFFFFF)}
        logging.debug('RAPIDUPLOAD DATA ' + str(data))
        #url = 'http://pan.baidu.com/api/rapidupload'
        return self._request('rapidupload', 'rapidupload', data=data, **kwargs)

    def search(self, path, keyword, page=1, recursion=1, limit=1000, **kwargs):
        """
        page: which page to return
        limit: items per page
        return: requests.Repsonse
			same as self.list_files()
        """
        params = {'dir': path,
                  'recursion': recursion,
                  'key': keyword,
                  'page': page,
                  'num': limit}

        #url = 'http://pan.baidu.com/api/search'

        return self._request('search', 'search', extra_params=params, **kwargs)

    def thumbnail(self, path, height, width, quality=100, **kwargs):
        """
        quality: thumbnail quality, 100 dfl
        return: requests.Response
			* 404 no thumbnail
        """
        params = {'ec': 1,
                  'path': path,
                  'quality': quality,
                  'width': width,
                  'height': height}

        url = 'http://{0}/rest/2.0/pcs/thumbnail'.format(BAIDUPCS_SERVER)
        return self._request('thumbnail', 'generate', url=url, extra_params=params, **kwargs)

    def meta(self, file_list, **kwargs):
        """
		get the meta information of the file
        file_list: ['/a.txt', '/b.txt']
        return: requests.Response
		    * file doesn't exist
            {"errno":12,"info":[{"errno":-9}],"request_id":3294861771}
            * file exist 
            {
                "errno": 0,
                "info": [
                    {
                        "fs_id": file id, 
                        "path": "/xxx.rar",
                        "server_filename": filename,
                        "size": 8292134,
                        "server_mtime": 1391274570,
                        "server_ctime": 1391274570,
                        "local_mtime": 1391274570,
                        "local_ctime": 1391274570,
                        "isdir": 0,
                        "category": 6,
                        "path_md5": 279827390796736883,
                        "delete_fs_id": 0,
                        "object_key": "84221121-2193956150-1391274570512754",
                        "block_list": [
                        ],
                        "md5": "76b469302a02b42fd0a548f1a50dd8ac",
                        "errno": 0
                    }
                ],
                "request_id": 2964868977
            }

        """
        if not isinstance(file_list, list):
            file_list = [file_list]
        data = {'target': json.dumps(file_list)}

        return self._request('filemetas?blocks=0&dlink=1', 'filemetas', data=data, **kwargs)

    def check_file_blocks(self, path, size, block_list, **kwargs):
        """
		file blocks checking
        path: file path 
        size: file size 
        block_list: file blocks list, md5 of file to upload
        return: requests.Response
			{
				"errno": 0,
				"path": "/18.rar",
				"request_id": 2462633013,
				"block_list": [
					"8da0ac878f3702c0768dc6ea6820d3ff",
					"3c1eb99b0e64993f38cd8317788a8855"
				]
			}

        """

        data = {'path': path,
                'size': size,
                'isdir': 0,
                'block_list': json.dumps(block_list)}

        return self._request('precreate', 'post', data=data, **kwargs)

