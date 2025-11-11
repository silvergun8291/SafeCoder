"""
RAG-Enhanced Secure Code Fixer
KISA/OWASP/Code Vector DB + LLM을 활용한 시큐어 코딩 자동화 도구
"""

import os
import sys
from pathlib import Path
from typing import List, Dict, Any, Optional
from dotenv import load_dotenv

# LangChain imports
from langchain_upstage import ChatUpstage
from langchain_core.messages import SystemMessage, HumanMessage

# Qdrant & Retriever imports
from qdrant_client import QdrantClient

# 프로젝트 루트 경로 설정
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

# config_db 임포트
try:
    import config_db
    QDRANT_URL = config_db.QDRANT_URL
    QDRANT_API_KEY = config_db.QDRANT_API_KEY
    UPSTAGE_API_KEY = config_db.UPSTAGE_API_KEY
except ImportError as e:
    print(f"❌ config_db.py 임포트 실패: {e}")
    sys.exit(1)

# test_retrievers 모듈에서 Retriever 클래스 임포트
try:
    from test_retrievers import (
        CodeRetriever,
        TextRetriever,
        QueryRequest,
        ScanResultRequest,
        RetrievalResult
    )
except ImportError as e:
    print(f"❌ test_retrievers.py 임포트 실패: {e}")
    print("  ℹ️ test_retrievers.py가 같은 디렉토리에 있는지 확인하세요.")
    sys.exit(1)

# .env 로드
load_dotenv()
os.environ["UPSTAGE_API_KEY"] = UPSTAGE_API_KEY


# ============================================================
# RAG Context Formatter
# ============================================================

class RAGContextFormatter:
    """RAG 검색 결과를 LLM 프롬프트 형식으로 변환"""
    
    @staticmethod
    def format_code_examples(results: List[RetrievalResult]) -> str:
        """Code DB 검색 결과 포맷팅"""
        if not results:
            return "No code examples found."
        
        formatted = []
        for i, result in enumerate(results, 1):
            payload = result.payload
            formatted.append(f"""
### 🔒 Secure Code Example {i} (Relevance: {result.score:.3f})
**CWE-{payload.cwe_id}**: {payload.description or 'N/A'}
**Language**: {payload.language or 'N/A'}

**❌ Vulnerable Pattern**:
```
{payload.vulnerable_code or 'N/A'}
```

**✅ Secure Pattern**:
```
{payload.safe_code or 'N/A'}
```

**Key Improvements**: 
Compare the vulnerable and secure patterns above to understand the security fixes applied.
""")
        return "\n".join(formatted)
    
    @staticmethod
    def format_text_guidelines(results: List[RetrievalResult], source_name: str) -> str:
        """Text DB (KISA/OWASP) 검색 결과 포맷팅"""
        if not results:
            return f"No {source_name} guidelines found."
        
        formatted = []
        for i, result in enumerate(results, 1):
            payload = result.payload
            content = payload.page_content or "N/A"
            # 너무 긴 경우 2500자로 제한
            if len(content) > 2500:
                content = content[:2500] + "\n... [truncated for brevity]"
            
            formatted.append(f"""
### 📖 {source_name} Guideline {i} (Relevance: {result.score:.3f})
**Source**: {payload.source or 'N/A'}
**Language**: {payload.language or 'N/A'}

{content}
""")
        return "\n".join(formatted)


# ============================================================
# Scan Result Parser
# ============================================================

class ScanResultParser:
    """스캔 결과 JSON을 파싱하여 프롬프트 생성에 필요한 데이터 추출"""
    
    @staticmethod
    def parse_scan_result(
        scan_result: Dict[str, Any],
        source_code: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        스캔 결과 JSON을 파싱하여 프롬프트 생성용 데이터 추출
        
        Args:
            scan_result: 스캔 결과 JSON (aggregated_vulnerabilities 포함)
            source_code: 원본 소스 코드 전체 (선택사항, 제공 시 더 나은 결과)
        
        Returns:
            {
                "language": str,
                "total_vulnerabilities": int,
                "severity_summary": dict,
                "vulnerabilities": List[dict],
                "vulnerable_code": str,
                "source_code": str,
                "system_prompt": str,
                "user_prompt": str
            }
        """
        language = scan_result.get("language", "java")
        total_vulns = scan_result.get("total_vulnerabilities", 0)
        severity_summary = scan_result.get("severity_summary", {})
        aggregated_vulns = scan_result.get("aggregated_vulnerabilities", [])
        
        # 취약점 정보 추출 (RAG 검색용)
        vulnerabilities = []
        for vuln in aggregated_vulns:
            cwe_id = str(vuln.get("cwe", "0"))
            description = vuln.get("description", "")
            code_snippet = vuln.get("code_snippet", "")
            
            vulnerabilities.append({
                "cwe_id": cwe_id,
                "description": description,
                "code_snippet": code_snippet,
                "severity": vuln.get("severity", "unknown"),
                "line_start": vuln.get("line_start"),
                "scanner": vuln.get("scanner")
            })
        
        # System Prompt 생성
        system_prompt = ScanResultParser._build_system_prompt(
            total_vulns, 
            severity_summary, 
            vulnerabilities
        )
        
        # User Prompt 생성
        user_prompt = ScanResultParser._build_user_prompt(
            language,
            total_vulns,
            aggregated_vulns,
            source_code  # 원본 코드 전달
        )
        
        # 취약한 코드 전체 추출 (코드 스니펫 결합)
        vulnerable_code = ScanResultParser._extract_vulnerable_code(aggregated_vulns)
        
        return {
            "language": language,
            "total_vulnerabilities": total_vulns,
            "severity_summary": severity_summary,
            "vulnerabilities": vulnerabilities,
            "vulnerable_code": vulnerable_code,
            "source_code": source_code,  # 원본 코드 포함
            "system_prompt": system_prompt,
            "user_prompt": user_prompt
        }
    
    @staticmethod
    def _build_system_prompt(
        total_vulns: int, 
        severity_summary: Dict[str, int],
        vulnerabilities: List[Dict[str, Any]]
    ) -> str:
        """System Prompt 생성"""
        # CWE별 그룹화
        cwe_groups = {}
        for vuln in vulnerabilities:
            cwe_id = vuln["cwe_id"]
            severity = vuln["severity"]
            if cwe_id not in cwe_groups:
                cwe_groups[cwe_id] = {"count": 0, "severity": severity, "description": ""}
            cwe_groups[cwe_id]["count"] += 1
            if not cwe_groups[cwe_id]["description"]:
                # 첫 번째 설명을 간략하게 저장
                desc = vuln["description"][:100] if vuln["description"] else ""
                cwe_groups[cwe_id]["description"] = desc
        
        # CWE 요약 생성
        cwe_summary = []
        for cwe_id, info in cwe_groups.items():
            cwe_name = ScanResultParser._get_cwe_name(cwe_id)
            cwe_summary.append(
                f"- CWE-{cwe_id} ({cwe_name}): {info['count']} instance(s) - Severity: {info['severity'].upper()}"
            )
        
        cwe_summary_text = "\n".join(cwe_summary)
        
        return f"""You are a world-class security engineer with expertise in OWASP, CWE, and secure software development.

**Mission**: Transform vulnerable code into production-grade secure code following industry best practices.

**Security Framework** (OWASP/CWE Compliance):
- Apply OWASP Top 10 countermeasures
- Follow CWE mitigation guidelines
- Implement defense-in-depth strategy
- Use security-by-design principles

**Systematic Approach** (Chain-of-Thought):
For each vulnerability:
1. **Identify**: Understand the CWE type and attack surface
2. **Analyze**: Determine root cause and exploitation path
3. **Design**: Select optimal mitigation strategy
4. **Implement**: Apply secure coding patterns
5. **Verify**: Ensure no new vulnerabilities introduced

**Self-Review Process** (Recursive Criticism):
- Critique your own solution for potential weaknesses
- Identify edge cases or bypass scenarios
- Enhance with additional security layers
- Validate against real-world attack patterns

**Critical Vulnerabilities ({len(cwe_groups)} CWE categories)**:
{cwe_summary_text}

**Deliverable**:
- Fully secure, tested code
- Detailed security analysis
- Inline documentation of security measures"""
    
    @staticmethod
    def _build_user_prompt(
        language: str,
        total_vulns: int,
        vulnerabilities: List[Dict[str, Any]],
        source_code: Optional[str] = None
    ) -> str:
        """User Prompt 생성"""
        # 취약점 상세 리포트 생성
        vuln_reports = []
        for i, vuln in enumerate(vulnerabilities, 1):
            cwe_id = vuln.get("cwe", "0")
            severity = vuln.get("severity", "unknown").upper()
            location = f"{vuln.get('line_start', '?')}-{vuln.get('line_end', '?')}"
            description = vuln.get("description", "No description")
            code_snippet = vuln.get("code_snippet", "")
            scanner = vuln.get("scanner", "unknown")
            
            vuln_report = f"""### Vulnerability #{i}
- **CWE**: {cwe_id}
- **Severity**: {severity}
- **Location**: Line {location}
- **Scanner**: {scanner}
- **Description**: {description}

**Vulnerable Code Snippet**:
```
{code_snippet}
```
"""
            vuln_reports.append(vuln_report)
        
        vuln_reports_text = "\n".join(vuln_reports)
        
        # 원본 코드가 제공된 경우
        if source_code:
            return f"""# Security Vulnerability Remediation Request

**Language**: {language.upper()}
**Total Vulnerabilities**: {total_vulns}

## Original Source Code

```{language}
{source_code}
```

## Detailed Vulnerability Report

{vuln_reports_text}

## Task

Generate **COMPLETE, SECURE CODE** that:
1. Fixes ALL identified vulnerabilities above
2. Maintains original functionality
3. Follows language-specific best practices
4. Includes comprehensive error handling
5. Adds security-focused inline comments explaining each fix
6. Returns the FULL, EXECUTABLE source code (not just snippets)"""
        
        # 원본 코드가 없는 경우 (code_snippet만 사용)
        else:
            return f"""# Security Vulnerability Remediation Request

**Language**: {language.upper()}
**Total Vulnerabilities**: {total_vulns}

## Detailed Vulnerability Report

{vuln_reports_text}

## Task

Generate complete, secure code that:
1. Fixes all identified vulnerabilities
2. Maintains original functionality
3. Follows language-specific best practices
4. Includes comprehensive error handling
5. Adds security-focused comments"""
    
    @staticmethod
    def _extract_vulnerable_code(vulnerabilities: List[Dict[str, Any]]) -> str:
        """취약한 코드 스니펫들을 결합"""
        code_snippets = []
        for vuln in vulnerabilities:
            snippet = vuln.get("code_snippet", "")
            if snippet and snippet not in code_snippets:
                code_snippets.append(snippet)
        return "\n\n".join(code_snippets)
    
    @staticmethod
    def _get_cwe_name(cwe_id: str) -> str:
        """CWE ID로 이름 매핑 (주요 CWE만)"""
        cwe_map = {
            "22": "Path Traversal",
            "78": "OS Command Injection",
            "79": "Cross-site Scripting (XSS)",
            "89": "SQL Injection",
            "94": "Code Injection",
            "119": "Buffer Overflow",
            "200": "Information Exposure",
            "287": "Improper Authentication",
            "352": "CSRF",
            "502": "Deserialization",
            "611": "XML External Entity (XXE)",
            "798": "Hardcoded Credentials",
            "0": "Unknown/Generic"
        }
        return cwe_map.get(cwe_id, f"CWE-{cwe_id}")


# ============================================================
# RAG-Enhanced Secure Code Fixer
# ============================================================

class SecureCodeFixer:
    """RAG + LLM 기반 시큐어 코드 생성기 (KISA + OWASP + Code Examples)"""
    
    def __init__(
        self,
        qdrant_url: str,
        qdrant_api_key: str,
        upstage_api_key: str,
        temperature: float = 0.0,
        top_p: float = 0.01,
        seed: int = 42
    ):
        """
        초기화
        
        Args:
            qdrant_url: Qdrant 서버 URL
            qdrant_api_key: Qdrant API 키
            upstage_api_key: Upstage API 키
            temperature: LLM temperature (0.0 = 결정적)
            top_p: nucleus sampling 파라미터
            seed: 재현성을 위한 시드
        """
        # Qdrant 클라이언트 초기화
        self.qdrant_client = QdrantClient(
            url=qdrant_url,
            api_key=qdrant_api_key,
            prefer_grpc=False
        )
        
        # Retriever 초기화
        self.code_retriever = CodeRetriever(self.qdrant_client)
        self.text_retriever = TextRetriever(self.qdrant_client)
        
        # LLM 초기화
        self.llm = ChatUpstage(
            model="solar-pro2",
            temperature=temperature,
            top_p=top_p,
            seed=seed,
            max_tokens=4096
        )
        
        self.formatter = RAGContextFormatter()
    
    def retrieve_security_context(
        self,
        language: str,
        vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """
        취약점 정보를 기반으로 RAG 검색 수행
        
        Args:
            language: 프로그래밍 언어 (java, python)
            vulnerabilities: 취약점 목록 [{"cwe_id": "89", "description": "...", "code_snippet": "..."}]
        
        Returns:
            검색된 보안 가이드라인 컨텍스트 (Code Examples, KISA, OWASP)
        """
        context = {
            "code_examples": [],
            "kisa_guidelines": [],
            "owasp_guidelines": []
        }
        
        for vuln in vulnerabilities:
            cwe_id = vuln.get("cwe_id", "0")
            description = vuln.get("description", "")
            code_snippet = vuln.get("code_snippet", "")
            
            # 1. Code DB 검색 (유사한 취약점 코드 예제)
            try:
                code_request = ScanResultRequest(
                    cwe_id=cwe_id,
                    language=language,
                    code_snippet=code_snippet,
                    description=description,
                    top_k=2  # 각 CWE당 2개 예제
                )
                code_results = self.code_retriever.query(code_request)
                context["code_examples"].extend(code_results)
            except Exception as e:
                print(f"  ⚠️ Code DB 검색 실패 (CWE-{cwe_id}): {e}")
            
            # 2. KISA 가이드라인 검색 (언어별 분기)
            try:
                query = f"CWE-{cwe_id} {description}"
                kisa_request = QueryRequest(query=query, top_k=3)  # KISA 중요하므로 3개
                
                if language.lower() == "java":
                    kisa_results = self.text_retriever.query_kisa_java(kisa_request)
                elif language.lower() == "python":
                    kisa_results = self.text_retriever.query_kisa_python(kisa_request)
                else:
                    # 언어 명시 안 된 경우 Java 기본
                    kisa_results = self.text_retriever.query_kisa_java(kisa_request)
                
                context["kisa_guidelines"].extend(kisa_results)
            except Exception as e:
                print(f"  ⚠️ KISA 검색 실패 (CWE-{cwe_id}): {e}")
            
            # 3. OWASP 검색
            try:
                owasp_request = QueryRequest(query=description, top_k=2)
                owasp_results = self.text_retriever.query_owasp(owasp_request)
                context["owasp_guidelines"].extend(owasp_results)
            except Exception as e:
                print(f"  ⚠️ OWASP 검색 실패 (CWE-{cwe_id}): {e}")
        
        return context
    
    def build_enhanced_prompt(
        self,
        base_system_prompt: str,
        user_prompt: str,
        rag_context: Dict[str, Any]
    ) -> tuple:
        """
        RAG 컨텍스트를 포함한 Enhanced 프롬프트 생성
        
        Args:
            base_system_prompt: 기본 시스템 프롬프트
            user_prompt: 사용자 프롬프트 (취약한 코드)
            rag_context: retrieve_security_context()의 결과
        
        Returns:
            (enhanced_system_prompt, user_prompt)
        """
        # RAG 컨텍스트 포맷팅
        code_examples_text = self.formatter.format_code_examples(
            rag_context.get("code_examples", [])
        )
        kisa_text = self.formatter.format_text_guidelines(
            rag_context.get("kisa_guidelines", []),
            "KISA Secure Coding (한국정보보호진흥원)"
        )
        owasp_text = self.formatter.format_text_guidelines(
            rag_context.get("owasp_guidelines", []),
            "OWASP Security"
        )
        
        # Enhanced System Prompt 생성
        enhanced_system_prompt = f"""{base_system_prompt}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## 📚 Retrieved Security Guidelines (RAG-Enhanced Context)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

You have been provided with authoritative security guidelines from:
1. **Proven Secure Code Examples** - Real-world implementations
2. **KISA Guidelines** - Korean government cybersecurity standards
3. **OWASP Best Practices** - Global industry security standards

**CRITICAL INSTRUCTION**: You MUST follow these retrieved guidelines EXACTLY.
These are not suggestions - they are mandatory requirements backed by government standards and industry consensus.

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
### 1️⃣ Secure Code Examples (Proven Patterns)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{code_examples_text}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
### 2️⃣ KISA Secure Coding Guidelines (Korean Government Standard)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{kisa_text}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
### 3️⃣ OWASP Security Best Practices (Global Standard)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

{owasp_text}

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## ⚠️ CRITICAL: Anti-Patterns You MUST Avoid
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Based on the guidelines above, you MUST NOT:

1. **❌ Path Traversal - Partial Path Vulnerability (CVE-2021-0004)**
```
// WRONG - Allows bypass via "/usr/outnot" when base is "/usr/out"
if (!path.startsWith(BASE_DIR))

// CORRECT - Include File.separator
if (!path.startsWith(BASE_DIR + File.separator))
```

2. **❌ Hardcoded Credentials (CWE-798)**
```
// WRONG
Connection conn = DriverManager.getConnection("...", "user", "password");

// CORRECT
String dbUser = System.getenv("DB_USER");
if (dbUser == null) throw new IllegalStateException("DB credentials not configured");
```

3. **❌ Process Execution Without Timeout (DoS Vulnerability)**
```
// WRONG - Can hang forever
int exitCode = process.waitFor();

// CORRECT - Apply timeout
if (!process.waitFor(5, TimeUnit.SECONDS)) {{
    process.destroyForcibly();
    throw new TimeoutException("Command execution timeout");
}}
```

4. **❌ Path Validation Without Symlink Resolution**
```
// WRONG - Symlinks can bypass
Path path = BASE_DIR.resolve(filename).normalize();

// CORRECT - Resolve symlinks
Path realPath = BASE_DIR.resolve(filename).toRealPath();
```

5. **❌ XXE - Enabled DOCTYPE/External Entities**
```
// WRONG - Default factory is vulnerable
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();

// CORRECT - Disable dangerous features
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
```

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## ✅ REQUIRED: Secure Patterns You MUST Implement
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Follow these patterns EXACTLY as shown in the guidelines above:

### Path Traversal Prevention (CWE-22)
```
Path baseDir = Paths.get("/data").toRealPath();  // Resolve symlinks
Path requestedPath = baseDir.resolve(filename).normalize();
Path realPath = requestedPath.toRealPath();  // Resolve again after combining

// CRITICAL: Include File.separator to prevent partial path attacks
if (!realPath.equals(baseDir) &&
    !realPath.startsWith(baseDir.toString() + File.separator)) {{
    throw new SecurityException("Path traversal detected");
}}
```

### SQL Injection Prevention (CWE-89)
```
// Database credentials from environment
String dbUrl = System.getenv("DB_URL");
String dbUser = System.getenv("DB_USER");
String dbPassword = System.getenv("DB_PASSWORD");

if (dbUrl == null || dbUser == null || dbPassword == null) {{
    throw new IllegalStateException("Database credentials not configured");
}}

// PreparedStatement with parameters
try (Connection conn = DriverManager.getConnection(dbUrl, dbUser, dbPassword);
     PreparedStatement stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?")) {{
    stmt.setString(1, userId);
    try (ResultSet rs = stmt.executeQuery()) {{
        // Process results and return DTO, not raw ResultSet
    }}
}}
```

### Command Injection Prevention (CWE-78)
```
// Option 1: Use Java native APIs instead of OS commands
InetAddress.getByName(host).isReachable(5000);

// Option 2: If OS command is necessary, use ProcessBuilder with timeout
ProcessBuilder pb = new ProcessBuilder("/bin/ping", "-c", "1", host);
pb.environment().clear();
pb.redirectErrorStream(true);
Process process = pb.start();

// Consume output stream to prevent buffer deadlock
try (BufferedReader reader = new BufferedReader(
        new InputStreamReader(process.getInputStream()))) {{
    reader.lines().forEach(line -> {{}});
}}

// Apply timeout
if (!process.waitFor(5, TimeUnit.SECONDS)) {{
    process.destroyForcibly();
    throw new TimeoutException();
}}
```

### XXE Prevention (CWE-611)
```
DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
factory.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
factory.setFeature("http://xml.org/sax/features/external-general-entities", false);
factory.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
factory.setFeature("http://apache.org/xml/features/nonvalidating/load-external-dtd", false);
factory.setXIncludeAware(false);
factory.setExpandEntityReferences(false);
```

━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
## 🎯 Your Task
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

Now fix the vulnerable code using the retrieved guidelines above.

**Requirements**:
1. Every security fix MUST be based on the guidelines above
2. Implement ALL required secure patterns exactly as shown
3. Avoid ALL listed anti-patterns
4. Add inline comments referencing which guideline you followed
5. Ensure the code is production-ready and passes all SAST scanners
"""
        
        return enhanced_system_prompt, user_prompt
    
    def generate_secure_code(
        self,
        language: str,
        vulnerable_code: str,
        vulnerabilities: List[Dict[str, Any]],
        system_prompt: str,
        user_prompt: str
    ) -> str:
        """
        RAG + LLM을 사용하여 시큐어 코드 생성
        
        Args:
            language: 프로그래밍 언어
            vulnerable_code: 취약한 원본 코드
            vulnerabilities: 취약점 목록
            system_prompt: 기본 시스템 프롬프트
            user_prompt: 기본 사용자 프롬프트
        
        Returns:
            LLM이 생성한 시큐어 코드
        """
        print("🔍 RAG 검색 중...")
        rag_context = self.retrieve_security_context(language, vulnerabilities)
        
        print(f"  ✅ Secure Code Examples: {len(rag_context['code_examples'])}개")
        print(f"  ✅ KISA Guidelines: {len(rag_context['kisa_guidelines'])}개")
        print(f"  ✅ OWASP Guidelines: {len(rag_context['owasp_guidelines'])}개")
        
        print("\n🧠 Enhanced 프롬프트 생성 중...")
        enhanced_system, enhanced_user = self.build_enhanced_prompt(
            system_prompt,
            user_prompt,
            rag_context
        )
        
        print("🚀 LLM 요청 전송 중...")
        messages = [
            SystemMessage(content=enhanced_system),
            HumanMessage(content=enhanced_user)
        ]
        
        try:
            response = self.llm.invoke(messages)
            print("✅ 응답 수신 완료.\n")
            return response.content
        except Exception as e:
            print(f"❌ LLM 요청 실패: {e}")
            return None
    
    def generate_secure_code_from_scan(
        self,
        scan_result: Dict[str, Any],
        source_code: Optional[str] = None
    ) -> Optional[str]:
        """
        스캔 결과 JSON을 받아서 시큐어 코드 생성 (API 통합용)
        
        Args:
            scan_result: 스캔 결과 JSON (aggregated_vulnerabilities 포함)
            source_code: 원본 소스 코드 전체 (선택사항, 제공 시 더 나은 결과)
        
        Returns:
            LLM이 생성한 시큐어 코드 또는 None
        """
        print("📋 스캔 결과 파싱 중...")
        
        # 스캔 결과 파싱
        parsed_data = ScanResultParser.parse_scan_result(scan_result, source_code)
        
        language = parsed_data["language"]
        vulnerabilities = parsed_data["vulnerabilities"]
        system_prompt = parsed_data["system_prompt"]
        user_prompt = parsed_data["user_prompt"]
        vulnerable_code = parsed_data["vulnerable_code"]
        
        print(f"  📊 언어: {language}")
        print(f"  📊 총 취약점: {parsed_data['total_vulnerabilities']}개")
        print(f"  📊 심각도: {parsed_data['severity_summary']}")
        
        # 시큐어 코드 생성
        return self.generate_secure_code(
            language=language,
            vulnerable_code=vulnerable_code,
            vulnerabilities=vulnerabilities,
            system_prompt=system_prompt,
            user_prompt=user_prompt
        )


# ============================================================
# 이 파일은 핵심 로직만 포함합니다.
# 테스트는 test_hardcoded.py 또는 test_scan_result.py를 실행하세요.
# ============================================================
