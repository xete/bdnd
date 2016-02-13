import json

class parser():
	def __init__(self):
		self.parse_func = {
			'list_files': self._list_files,
			'download_url': self._download_url,
		}
		self.json_dec = json.JSONDecoder()
		pass

	def parse(self, content, type=None):
		'''
		content: string to parse, normally response from server
		type: type selector
		'''
		if not type or not type in self.parse_func.keys():
			print 'type error'
			return
		return self.parse_func[type](self.json_dec.decode(content))
	
	def _list_files(self, content):
		files = []
		if 'list' in content.keys():
			for f in content['list']:
				files.append(f['server_filename'])
		return files 
				
	def _download_url(self, content):
		return content
		
		
