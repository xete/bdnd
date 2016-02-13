#!/usr/bin/env python

from baidupcsapi import PCS
from translate import json_parser
import os


class connect():
	def __init__(self, mode='non-interactive'):
		'''
		mode: interactive or not
		'''
		try:
			username = raw_input('username: ')
			os.system('stty -echo')
			password = raw_input('password: ')
			print '\n'
			os.system('stty echo')
			self.env = PCS(username, password)
		except:
			return None
		if not self.env:
			return None
		self._parse = json_parser.parser().parse
		self._cwd = '/'
		self._dirs = {}
		self._commands = {
			'ls': self._list_files,
			'readlink': self._download_url,
			'cd': self._change_dir,
		}
		self._mode = mode
		if self._mode == 'interactive':
			self._loop()

	def _loop(self):
		while True:
			input = raw_input(self._cwd+'>> ')
			if input in ['q', 'quit', 'exit', 'dis', 'disconnect']:
				break
			# need to type 'quit' more than once
			elif input in ['relogin']:
				self = connect(mode='interactive')
			arg_list = input.split(' ')
			if arg_list[0] in self._commands:
				args = arg_list[1:]
				# unpack arguments out of a list or tuple
				try:
					self._commands[arg_list[0]](*args)
				except:
					pass
	
	def attach(self):
		self._loop()
	
	def _list_files(self, *args):
		ret = {}
		if len(args) == 0:
			args = {self._cwd}
		for d in args:
			ret[d] = self._parse(self.env.list_files(d).content, type='list_files')
		if self._mode != 'interactive':
			return ret	
		else:
			for r in ret:
				for item in ret[r]:
					print '  '+item

	def _download_url(self, *args):
		ret = {}
		for f in args:
			try:
				ret[f] = self.env.download_url(f)
			except:
				ret[f] = None
		if self._mode != 'interactive':
			return ret	
		else:
			for r in ret:
				for item in ret[r]:
					print '  '+item if item else 'None'

	def _change_dir(self, arg):
		def format_arg(arg):
			if arg == '/':
				return arg
			if arg.endswith('/'):
				arg = arg[:-1]
			if arg == '..':
				arg = os.path.dirname(self._cwd)
				return arg
			if arg == '.':
				arg = self._cwd
				return arg
			# covert to absolute path
			if not arg.startswith('/'):
				if self._cwd == '/':
					arg = self._cwd + arg
				else:
					arg = self._cwd +'/'+ arg
			return arg
		arg = format_arg(arg)
		# cached directories
		if arg in self._dirs.keys():
			self._cwd = arg
		else:
			d = self._parse(self.env.list_files(arg).content, type='list_files')
			if d != []:
				self._cwd = arg	
				self._dirs[arg] = d
