from __future__ import annotations
import tree_sitter_javascript as tsjs
import tree_sitter_typescript as tsts
from tree_sitter import Language, Parser
from ..security import SecurityScanner

class JSTSParser:
    """
    Compiler front-end for JavaScript and TypeScript files using Tree-sitter.
    """
    JS_LANGUAGE = Language(tsjs.language())
    TSX_LANGUAGE = Language(tsts.language_tsx())
    
    COMPLEXITY_NODES = frozenset({
        "if_statement", "for_statement", "while_statement", 
        "catch_clause", "arrow_function", "function_declaration",
        "switch_statement", "ternary_expression"
    })

    def __init__(self, filepath: str, code: str) -> None:
        self.filepath = filepath
        self.code = code
        # Dynamically choose the grammar based on file extension
        if filepath.endswith(('.tsx', '.ts')):
            self.parser = Parser(self.TSX_LANGUAGE)
        else:
            self.parser = Parser(self.JS_LANGUAGE)

    def parse(self) -> dict[str, Any]:
        tree = self.parser.parse(bytes(self.code, "utf8"))
        root = tree.root_node

        complexity = 0
        imports = []
        exported_entities = []
        api_endpoints = []
        db_models = []
        state_mutations = 0
        concurrency_count = 0
        empty_catches = 0
        logged_catches = 0
        module_purpose = ""

        # 1. Extract Module Purpose (First block comment)
        for node in root.children[:10]: # Scan the top of the file
            if node.type == "comment":
                comment_text = node.text.decode("utf8")
                # Look for multi-line comments (/* or /**)
                if comment_text.startswith("/*"):
                    module_purpose = comment_text.strip("/* \n\t")
                    break

        def traverse(node):
            nonlocal complexity, state_mutations, concurrency_count, empty_catches, logged_catches
            
            node_type = node.type

            # Complexity
            if node_type in self.COMPLEXITY_NODES:
                complexity += 1

            # Concurrency (async/await)
            if node_type == "await_expression" or (node.is_named and node_type == "function_declaration" and "async" in node.text.decode("utf8")):
                concurrency_count += 1

            # State Mutations (Assignment expressions)
            if node_type == "assignment_expression":
                state_mutations += 1

            # ES6 Imports
            if node_type == "import_statement":
                for child in node.children:
                    if child.type == "string":
                        imports.append(child.text.decode("utf8").strip("'\""))

            # CommonJS Imports & API Endpoints & DB Models
            if node_type == "call_expression":
                func_node = node.child_by_field_name("function")
                args_node = node.child_by_field_name("arguments")
                
                if func_node and args_node:
                    func_text = func_node.text.decode("utf8")
                    
                    # require()
                    if func_text == "require":
                        for arg in args_node.children:
                            if arg.type == "string":
                                imports.append(arg.text.decode("utf8").strip("'\""))
                    
                    # API Routes (app.get, router.post, etc.)
                    elif any(method in func_text for method in {".get", ".post", ".put", ".delete", ".patch"}):
                        if "app" in func_text or "router" in func_text:
                            route_path = args_node.children[1].text.decode("utf8").strip("'\"") if len(args_node.children) > 1 else "unknown"
                            api_endpoints.append({"method": func_text.split(".")[-1].upper(), "path": route_path})
                    
                    # DB Operations (.save, .find, .query)
                    elif any(db_op in func_text for db_op in {".save", ".find", ".query", ".execute"}):
                        db_models.append(func_text.split(".")[0])

            # Exports
            if node_type == "export_statement":
                decl = node.child_by_field_name("declaration")
                if decl and decl.type in {"function_declaration", "class_declaration", "lexical_declaration"}:
                    name_node = decl.child_by_field_name("name") or (decl.children[1].child_by_field_name("name") if decl.type == "lexical_declaration" else None)
                    if name_node:
                        exported_entities.append(name_node.text.decode("utf8"))

            # Exception Handling Quality
            if node_type == "catch_clause":
                body = node.child_by_field_name("body")
                if body:
                    body_text = body.text.decode("utf8")
                    if "console." in body_text or "throw" in body_text:
                        logged_catches += 1
                    elif len(body.children) <= 2: # {} has 2 children in tree-sitter (the brackets)
                        empty_catches += 1

            for child in node.children:
                traverse(child)

        traverse(root)

        # Security Checks
        entropy_count, handles_pii = SecurityScanner.scan_string_literals_js(self.code)
        
        vulnerabilities = []
        if "eval(" in self.code:
            vulnerabilities.append(f"DANGEROUS: bare 'eval()' call in {self.filepath}")
        if "new Function(" in self.code:
            vulnerabilities.append(f"DANGEROUS: dynamic 'new Function()' call in {self.filepath}")

        return {
            "parse_error": None,
            "filepath": self.filepath,
            "imports": list(set(imports)),
            "astComplexity": complexity,
            "modulePurpose": module_purpose,
            "exportedEntities": list(set(exported_entities)),
            "apiEndpoints": api_endpoints,
            "databaseModels": list(set(db_models)),
            "stateMutations": state_mutations,
            "swallowsExceptions": empty_catches > logged_catches,
            "concurrencyDensity": concurrency_count,
            "isAsyncHeavy": concurrency_count >= 5,
            "highEntropySecrets": entropy_count,
            "handlesPII": handles_pii,
            "criticalVulnerabilities": vulnerabilities,
        }