import tree_sitter
from tree_sitter import Language, Parser
import os

class CodeParser:
    def __init__(self):
        self.parsers = {}
        self._init_parsers()
        
    def _init_parsers(self):
        try:
            import tree_sitter_python
            import tree_sitter_javascript
            import tree_sitter_php
            import tree_sitter_go
            import tree_sitter_java
            import tree_sitter_c
            import tree_sitter_cpp
            
            self.parsers['.py'] = Parser()
            self.parsers['.py'].set_language(tree_sitter_python.language())
            
            self.parsers['.js'] = Parser()
            self.parsers['.js'].set_language(tree_sitter_javascript.language())
            
            self.parsers['.jsx'] = self.parsers['.js']
            self.parsers['.ts'] = self.parsers['.js']
            self.parsers['.tsx'] = self.parsers['.js']
            
            self.parsers['.php'] = Parser()
            self.parsers['.php'].set_language(tree_sitter_php.language())
            
            self.parsers['.go'] = Parser()
            self.parsers['.go'].set_language(tree_sitter_go.language())
            
            self.parsers['.java'] = Parser()
            self.parsers['.java'].set_language(tree_sitter_java.language())
            
            self.parsers['.c'] = Parser()
            self.parsers['.c'].set_language(tree_sitter_c.language())
            
            self.parsers['.cpp'] = Parser()
            self.parsers['.cpp'].set_language(tree_sitter_cpp.language())
            
            self.parsers['.cc'] = self.parsers['.cpp']
            self.parsers['.h'] = self.parsers['.c']
            self.parsers['.hpp'] = self.parsers['.cpp']
            
        except Exception as e:
            pass
            
    def parse(self, file_path: str, content: str):
        ext = os.path.splitext(file_path)[1]
        parser = self.parsers.get(ext)
        
        if parser:
            try:
                return parser.parse(bytes(content, 'utf8'))
            except:
                return None
        return None
