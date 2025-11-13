"""
Java/Python 보안 취약점 Rule 생성기
- 16개 핵심 CWE (Java/Python 관련만)
"""

from typing import Dict, Optional, List
import re
import logging

logger = logging.getLogger(__name__)


class JavaPythonRuleGenerator:
    """Java/Python 전용 Rule 생성기"""

    def __init__(self, llm_client=None):
        self.llm = llm_client
        self.examples = self._load_java_python_examples()

    @staticmethod
    def _load_java_python_examples() -> Dict[str, Dict]:
        """Java/Python 관련 CWE만 (16개)"""
        return {
            # === Injection 계열 ===
            "CWE-89": {  # SQL Injection
                "category": "Injection",
                "languages": ["java", "python"],
                "java_before": "Statement stmt = conn.createStatement();",
                "java_after": "PreparedStatement stmt = conn.prepareStatement(query);",
                "python_before": "cursor.execute(f'SELECT * FROM users WHERE id={user_id}')",
                "python_after": "cursor.execute('SELECT * FROM users WHERE id=?', (user_id,))",
            },
            "CWE-78": {  # OS Command Injection
                "category": "Injection",
                "languages": ["java", "python"],
                "java_before": "Runtime.getRuntime().exec(cmd);",
                "java_after": "new ProcessBuilder(cmd).start();",
                "python_before": "os.system(cmd)",
                "python_after": "subprocess.run(cmd, shell=False)",
            },
            "CWE-79": {  # XSS
                "category": "Injection",
                "languages": ["java", "python"],
                "java_before": "out.println(userInput);",
                "java_after": "out.println(StringEscapeUtils.escapeHtml4(userInput));",
                "python_before": "return f'<div>{user_input}</div>'",
                "python_after": "return f'<div>{escape(user_input)}</div>'",
            },
            "CWE-94": {  # Code Injection
                "category": "Injection",
                "languages": ["java", "python"],
                "java_before": "scriptEngine.eval(userInput);",
                "java_after": "// Remove eval or use safe sandbox",
                "python_before": "eval(user_input)",
                "python_after": "ast.literal_eval(user_input)",
            },

            # === Access Control ===
            "CWE-22": {  # Path Traversal
                "category": "Access Control",
                "languages": ["java", "python"],
                "java_before": "new FileInputStream(filename);",
                "java_after": "Files.readAllBytes(basePath.resolve(filename).normalize());",
                "python_before": "open(filename, 'r')",
                "python_after": "open(safe_join(base_dir, filename), 'r')",
            },
            "CWE-434": {  # File Upload
                "category": "Access Control",
                "languages": ["java", "python"],
                "java_before": "file.transferTo(new File(path));",
                "java_after": "if (isValidFileType(file)) file.transferTo(sanitized);",
                "python_before": "file.save(path)",
                "python_after": "if is_safe_filename(file): file.save(secure_path)",
            },

            # === Cryptography ===
            "CWE-327": {  # Weak Crypto
                "category": "Cryptography",
                "languages": ["java", "python"],
                "java_before": "MessageDigest.getInstance('MD5');",
                "java_after": "MessageDigest.getInstance('SHA-256');",
                "python_before": "hashlib.md5(data)",
                "python_after": "hashlib.sha256(data)",
            },
            "CWE-330": {  # Weak Random
                "category": "Cryptography",
                "languages": ["java", "python"],
                "java_before": "new Random();",
                "java_after": "new SecureRandom();",
                "python_before": "random.random()",
                "python_after": "secrets.SystemRandom()",
            },
            "CWE-798": {  # Hardcoded Credentials
                "category": "Cryptography",
                "languages": ["java", "python"],
                "java_before": "getConnection(url, 'admin', 'password');",
                "java_after": "getConnection(url, System.getenv('USER'), System.getenv('PASS'));",
                "python_before": "conn = connect('localhost', 'admin', 'pass123')",
                "python_after": "conn = connect('localhost', os.getenv('USER'), os.getenv('PASS'))",
            },

            # === Deserialization ===
            "CWE-502": {  # Unsafe Deserialization
                "category": "Deserialization",
                "languages": ["java", "python"],
                "java_before": "new ObjectInputStream(input);",
                "java_after": "new ValidatingObjectInputStream(input, allowedClasses);",
                "python_before": "pickle.loads(data)",
                "python_after": "json.loads(data)",
            },

            # === XML ===
            "CWE-611": {  # XXE
                "category": "XML",
                "languages": ["java", "python"],
                "java_before": "DocumentBuilderFactory.newInstance();",
                "java_after": "factory.setFeature('disallow-doctype-decl', true);",
                "python_before": "ET.parse(xml_file)",
                "python_after": "defusedxml.ElementTree.parse(xml_file)",
            },

            # === SSRF ===
            "CWE-918": {  # SSRF
                "category": "SSRF",
                "languages": ["java", "python"],
                "java_before": "new URL(userInput).openConnection();",
                "java_after": "validateURL(userInput).openConnection();",
                "python_before": "requests.get(user_url)",
                "python_after": "requests.get(validate_url(user_url))",
            },
            "CWE-601": {  # Open Redirect
                "category": "SSRF",
                "languages": ["java", "python"],
                "java_before": "response.sendRedirect(url);",
                "java_after": "response.sendRedirect(validateRedirect(url));",
                "python_before": "return redirect(user_url)",
                "python_after": "return redirect(validate_redirect(user_url))",
            },

            # === Validation ===
            "CWE-20": {  # Input Validation
                "category": "Validation",
                "languages": ["java", "python"],
                "java_before": "process(userInput);",
                "java_after": "if (validate(userInput)) process(userInput);",
                "python_before": "result = process(user_input)",
                "python_after": "if validate(user_input): result = process(user_input)",
            },

            # === Authentication ===
            "CWE-287": {  # Authentication
                "category": "Authentication",
                "languages": ["java", "python"],
                "java_before": "if (user.equals(username))",
                "java_after": "if (secureCompare(user, username))",
                "python_before": "if password == stored_password:",
                "python_after": "if secrets.compare_digest(password, stored_password):",
            },
            "CWE-352": {  # CSRF
                "category": "Authentication",
                "languages": ["java", "python"],
                "java_before": "@PostMapping('/transfer')",
                "java_after": "@PostMapping('/transfer') + CSRF token validation",
                "python_before": "@app.route('/transfer', methods=['POST'])",
                "python_after": "@app.route('/transfer') + @csrf.exempt removed",
            },
        }

    def generate_rule(
            self,
            before_code: str,
            after_code: str,
            ast_result: Dict,
            cwe: str = None,
            language: str = "java",
            feedback: str = None
    ) -> Optional[Dict]:
        """Rule 생성 (이스케이프 처리 완벽)"""

        # 관련 예시 선택
        examples = self._select_examples(cwe, language)

        # 프롬프트 생성
        prompt = self._build_safe_prompt(
            before_code, after_code, ast_result, cwe, language, examples, feedback
        )

        if self.llm is None:
            print(prompt)
            return None

        try:
            response = self.llm.generate(prompt, temperature=0.2)
            try:
                txt = str(response) if response is not None else "<None>"
                # 길이 제한(최대 4000자)으로 로그 과다 방지
                max_len = 4000
                if len(txt) > max_len:
                    logger.info("LLM 응답 원문 (truncated %d/%d): %s...", max_len, len(txt), txt[:max_len])
                else:
                    logger.info("LLM 응답 원문: %s", txt)
            except Exception:
                pass
            return self._parse_response(response)
        except Exception as e:
            print(f"Error: {e}")
            return None

    @staticmethod
    def _build_safe_prompt(
            before: str,
            after: str,
            ast: Dict,
            cwe: str,
            lang: str,
            examples: List[Dict],
            feedback: str = None
    ) -> str:
        """이스케이프 안전한 프롬프트"""

        # 예시 포맷팅
        example_text = ""
        for i, ex in enumerate(examples, 1):
            if lang == "java":
                ex_before = ex.get("java_before", "")
                ex_after = ex.get("java_after", "")
            else:
                ex_before = ex.get("python_before", "")
                ex_after = ex.get("python_after", "")

            example_text += f"\n### Example {i}: {ex.get('category', 'Security')}\n"
            example_text += f"Before: {ex_before}\n"
            example_text += f"After: {ex_after}\n"

        prompt = f"""Role: Security Code Transformation Expert

                    Generate a Piranha rule for this vulnerability fix.
                    
                    Context:
                    - CWE: {cwe or 'Unknown'}
                    - Language: {lang}
                    - Changes: {', '.join(ast['removed_methods'][:3])} -> {', '.join(ast['added_methods'][:3])}
                    
                    Vulnerable Code:
                    {before[:400]}
                    
                    Secure Code:
                    {after[:400]}
                    
                    Relevant Examples:
                    {example_text}
                    
                    Task:
                    1. Identify the core security fix
                    2. Extract metavariables ($stmt, $conn, etc.)
                    3. Generate Piranha rule
                    
                    STRICT CONSTRAINTS (must follow exactly):
                    - Allowed fields in Rule(...): name, query, replace_node, replace, holes
                    - Disallowed: replacement, Pattern, Node, any additional imports besides 'from polyglot_piranha import Rule'
                    - Output must be a single Python code block only, no extra text or comments
                    
                    Output (Python code):
                    
                    ```python
                    from polyglot_piranha import Rule
                    
                    rule = Rule(
                    name="cwe_pattern_name",
                    query='''cs vulnerable_pattern''',
                    replace_node="cs vulnerable_pattern",
                    replace='''cs secure_pattern''',
                    holes={{"$var": {{"cs": "$var"}}}}
                    )
                    ```
                    """

        if feedback:
            prompt += f"""
                        ## Previous Attempt Feedback

                        Your previous rule failed validation with this error:
                        {feedback}
                        
                        **Action Required:**
                        Please analyze the error and generate a corrected rule.
                        Common issues:
                        - Incorrect metavariable names
                        - Missing query patterns
                        - Wrong tree-sitter syntax
                        """

        return prompt

    def _select_examples(self, cwe: str, language: str) -> List[Dict]:
        """관련 예시 2개 선택"""
        examples = []

        # 동일 CWE
        if cwe and cwe in self.examples:
            ex = self.examples[cwe]
            if language in ex.get("languages", []):
                examples.append(ex)

        # 유사 카테고리에서 1개 추가
        if len(examples) < 2 and cwe and cwe in self.examples:
            category = self.examples[cwe].get("category")
            for cwe_id, ex in self.examples.items():
                if (cwe_id != cwe and
                        ex.get("category") == category and
                        language in ex.get("languages", [])):
                    examples.append(ex)
                    break

        return examples[:2]

    @staticmethod
    def _parse_response(response: str) -> Optional[Dict]:
        """응답 파싱"""
        if not response:
            return None

        text = str(response)

        # 1) 언어 명시된 코드펜스 우선 탐색: ```python\n ... ``` (대소문자 무시)
        m = re.search(r"```\s*(?:python|py)\s*\n(.*?)```", text, re.DOTALL | re.IGNORECASE)
        if not m:
            # 2) 일반 코드펜스: ```\n ... ```
            m = re.search(r"```\s*\n(.*?)```", text, re.DOTALL)

        if m:
            rule_code = m.group(1).strip()
        else:
            # 3) 폴백: 응답 전체에서 'rule = Rule(' 주변을 포함한 텍스트 사용
            #    너무 길면 그대로 넘기면 밸리데이터에서 거를 수 있도록 함
            rule_code = text.strip()

        # 사후 정규화: 지원하지 않는 필드/임포트 교정
        rule_code = JavaPythonRuleGenerator._sanitize_rule_code(rule_code)

        name_match = re.search(r'name=["\']([^"\']+)["\']', rule_code)

        return {
            "rule_code": rule_code,
            "name": name_match.group(1) if name_match else "unknown"
        }

    @staticmethod
    def _sanitize_rule_code(code: str) -> str:
        """
        LLM 출력 정규화:
        - replacement 키워드를 replace로 변경
        - 금지된 import 제거: Pattern, Node 등
        - 중복 공백 정리(보수적으로 최소한만)
        """
        try:
            s = code
            # replacement= -> replace= (양쪽 공백 허용)
            s = re.sub(r"\breplacement\s=", "replace=", s)
            # 금지 import 제거
            s = re.sub(r"^\s*from\s+polyglot_piranha\s+import\s+Rule\s*,\s*Pattern\s*\n", "from polyglot_piranha import Rule\n", s, flags=re.MULTILINE)
            s = re.sub(r"^\s*from\s+polyglot_piranha\s+import\s+Pattern\s*\n", "", s, flags=re.MULTILINE)
            s = re.sub(r"^\s*from\s+polyglot_piranha\s+import\s+Node\s*\n", "", s, flags=re.MULTILINE)
            # 혹시 다른 모듈에서 Pattern/Node를 임포트한 경우도 제거
            s = re.sub(r"^\s*from\s+polyglot_piranha\s+import\s+.*\bPattern\b.*\n", "", s, flags=re.MULTILINE)
            s = re.sub(r"^\s*from\s+polyglot_piranha\s+import\s+.*\bNode\b.*\n", "", s, flags=re.MULTILINE)
            return s
        except Exception:
            return code