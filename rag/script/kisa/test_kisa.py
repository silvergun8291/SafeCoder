import os
import sys
import warnings
from pathlib import Path
from dotenv import load_dotenv
from qdrant_client import QdrantClient
from langchain_upstage.embeddings import UpstageEmbeddings

warnings.filterwarnings('ignore', message='Api key is used with an insecure connection')

load_dotenv()

config_dir = Path(__file__).resolve().parent.parent
if str(config_dir) not in sys.path:
    sys.path.insert(0, str(config_dir))

try:
    import config_db

    QDRANT_URL = config_db.QDRANT_URL
    QDRANT_API_KEY = config_db.QDRANT_API_KEY
    UPSTAGE_API_KEY = config_db.UPSTAGE_API_KEY
    TEXT_EMBEDDING_MODEL = config_db.TEXT_EMBEDDING_MODEL
except ImportError as e:
    print(f"🚨 config_db.py 임포트 실패: {e}")
    sys.exit(1)

os.environ["UPSTAGE_API_KEY"] = UPSTAGE_API_KEY
EMBEDDING_MODEL = UpstageEmbeddings(model=TEXT_EMBEDDING_MODEL)

COLLECTION_NAME = "kisa_raw_db"

# KISA 49개 취약점 키워드 매핑 (개선됨)
VULNERABILITY_KEYWORDS = {
    # 입력 데이터 검증 및 표현 (17개)
    "SQL Injection": {
        "primary": ["PreparedStatement", "setString", "바인딩", "파라미터", "executeQuery", "placeholder", "parameterized",
                    "쿼리", "SQL", "injection"],
        "secondary": ["execute", "ORM", "Hibernate", "binding", "statement", "쿼리문", "조건"]
    },
    "OS Command Injection": {
        "primary": ["Runtime.exec", "ProcessBuilder", "명령어", "실행", "command", "process", "subprocess"],
        "secondary": ["exec", "shell", "bash", "system"]
    },
    "Path Traversal": {
        "primary": ["경로", "directory", "path", "file", "파일", "조작", "manipulation"],
        "secondary": ["/../", "../", "resolved", "canonical", "normalize"]
    },
    "XSS": {
        "primary": ["replaceAll", "c:out", "필터링", "sanitiz", "JSTL", "encoding", "escape"],
        "secondary": ["치환", "라이브러리", "Lucy", "ESAPI", "Encoder", "XSS"]
    },
    "File Upload": {
        "primary": ["파일", "검증", "확장자", "MIME", "type", "upload", "extension"],
        "secondary": ["filename", "size", "content", "virus", "scanning"]
    },
    "LDAP Injection": {
        "primary": ["LDAP", "ldap", "filter", "필터", "escape", "DN", "검증"],
        "secondary": ["directory", "authentication", "bind"]
    },
    "XPath Injection": {
        "primary": ["XPath", "xpath", "expression", "식", "XML", "검증"],
        "secondary": ["node", "select", "query"]
    },
    "XML External Entity": {
        "primary": ["XXE", "XML", "DTD", "entity", "external", "개체", "참조"],
        "secondary": ["parser", "document", "factory"]
    },
    "XML Injection": {
        "primary": ["XML", "injection", "삽입", "tag", "태그", "element"],
        "secondary": ["parse", "document", "builder"]
    },
    "CSRF": {
        "primary": ["CSRF", "token", "토큰", "request", "요청", "forgery"],
        "secondary": ["validate", "verify", "check"]
    },
    "SSRF": {
        "primary": ["SSRF", "request", "URL", "요청", "검증", "validation"],
        "secondary": ["whitelist", "filter", "domain"]
    },
    "HTTP Response Splitting": {
        "primary": ["응답", "분할", "헤더", "header", "CRLF", "줄바꿈"],
        "secondary": ["newline", "injection", "response"]
    },
    "Integer Overflow": {
        "primary": ["오버플로우", "overflow", "정수", "integer", "범위", "range"],
        "secondary": ["max", "min", "boundary", "check"]
    },
    "Format String": {
        "primary": ["format", "포맷", "string", "문자열", "%x", "%s"],
        "secondary": ["printf", "scanf", "buffer"]
    },
    "URL Redirection": {
        "primary": ["리다이렉트", "redirect", "URL", "자동", "automatic", "whitelist"],
        "secondary": ["trusted", "domain", "validation"]
    },
    "Insecure Deserialization": {
        "primary": ["직렬화", "deserialization", "serializable", "object", "stream"],
        "secondary": ["readObject", "writeObject", "gadget"]
    },
    "Resource Injection": {
        "primary": ["자원", "리소스", "injection", "삽입", "경로", "path"],
        "secondary": ["file", "database", "connection"]
    },

    # 보안 기능 (16개)
    "Authentication": {
        "primary": ["인증", "authentication", "password", "비밀번호", "login", "로그인"],
        "secondary": ["verify", "validate", "hash", "salt"]
    },
    "Authorization": {
        "primary": ["인가", "authorization", "권한", "access", "role", "permission"],
        "secondary": ["check", "verify", "grant"]
    },
    "Weak Encryption": {
        "primary": ["암호화", "encryption", "algorithm", "알고리즘", "weak", "DES", "MD5"],
        "secondary": ["cipher", "key", "AES", "SHA"]
    },
    "Hardcoded Secret": {
        "primary": ["하드코드", "hardcoded", "secret", "비밀", "키", "key", "password"],
        "secondary": ["configuration", "config", "embedded"]
    },
    "Weak Random": {
        "primary": ["난수", "random", "Random", "seed", "시드", "predictable"],
        "secondary": ["SecureRandom", "cryptographic"]
    },
    "Weak Password": {
        "primary": ["약한", "weak", "비밀번호", "password", "정책", "policy"],
        "secondary": ["length", "complexity", "dictionary"]
    },
    "Digital Signature": {
        "primary": ["서명", "signature", "verify", "검증", "sign", "signing"],
        "secondary": ["certificate", "algorithm"]
    },
    "Certificate": {
        "primary": ["인증서", "certificate", "검증", "verify", "유효성", "validity"],
        "secondary": ["expiry", "chain", "CA"]
    },
    "Cookies": {
        "primary": ["쿠키", "cookies", "저장", "sensitive", "중요", "정보"],
        "secondary": ["HttpOnly", "Secure", "SameSite"]
    },
    "Debug Code": {
        "primary": ["디버그", "debug", "주석", "comment", "정보", "information"],
        "secondary": ["remove", "cleanup", "release"]
    },
    "Hash Function": {
        "primary": ["해시", "hash", "salt", "솔트", "일방향", "one-way"],
        "secondary": ["bcrypt", "scrypt", "PBKDF2"]
    },
    "Integrity": {
        "primary": ["무결성", "integrity", "체크", "check", "download", "다운로드"],
        "secondary": ["verify", "hash", "signature"]
    },
    "Login Attempt": {
        "primary": ["반복", "attempt", "로그인", "login", "제한", "limit"],
        "secondary": ["throttle", "delay", "lockout"]
    },
    "Null Pointer": {
        "primary": ["Null", "NPE", "포인터", "pointer", "체크", "check"],
        "secondary": ["validation", "safe", "optional"]
    },

    # 시간 및 상태 (2개)
    "Race Condition": {
        "primary": ["경쟁", "race", "condition", "TOCTOU", "동시성", "concurrency"],
        "secondary": ["lock", "synchronization", "atomic"]
    },

    # 에러 처리 (3개)
    "Error Message": {
        "primary": ["에러", "error", "메시지", "message", "정보", "information", "노출"],
        "secondary": ["expose", "stack", "trace"]
    },
    "Error Handling": {
        "primary": ["예외", "exception", "처리", "handling", "catch", "try"],
        "secondary": ["finally", "error", "recovery"]
    },

    # 캡슐화 (4개)
    "Session": {
        "primary": ["세션", "session", "request.session", "데이터", "노출", "저장", "request"],
        "secondary": ["private", "protected", "scope", "쿠키", "cookies", "권한"]
    },
    "Array Bounds": {
        "primary": ["배열", "array", "범위", "bounds", "index", "인덱스"],
        "secondary": ["check", "length", "overflow"]
    },

    # API 오용 (2개)
    "DNS Lookup": {
        "primary": ["DNS", "lookup", "검증", "validation", "보안", "security"],
        "secondary": ["trust", "verify", "domain"]
    },
    "API Misuse": {
        "primary": ["API", "오용", "misuse", "부적절", "improper", "사용"],
        "secondary": ["usage", "pattern", "best-practice"]
    }
}


def extract_keywords(query: str) -> dict:
    """쿼리에서 관련 취약점 키워드 자동 추출"""
    keywords = {
        'primary': [],
        'secondary': []
    }

    query_lower = query.lower()

    # 모든 취약점 키워드를 순회
    for vuln_name, kw_dict in VULNERABILITY_KEYWORDS.items():
        # 취약점 이름이나 키워드에 매칭되면 해당 키워드 추가
        if vuln_name.lower() in query_lower:
            keywords['primary'].extend(kw_dict['primary'])
            keywords['secondary'].extend(kw_dict['secondary'])
        else:
            # 개별 키워드 매칭
            for kw in kw_dict['primary']:
                if kw.lower() in query_lower:
                    keywords['primary'].extend(kw_dict['primary'])
                    keywords['secondary'].extend(kw_dict['secondary'])
                    break

    # 중복 제거
    keywords['primary'] = list(set(keywords['primary']))
    keywords['secondary'] = list(set(keywords['secondary']))

    return keywords


def rerank_results(results: list, query: str, language: str = None) -> list:
    """키워드 매칭으로 결과 재정렬 (개선됨)"""
    keywords_dict = extract_keywords(query)
    primary = keywords_dict.get('primary', [])
    secondary = keywords_dict.get('secondary', [])

    scored_results = []
    for result in results:
        score = result.score
        content = result.payload.get('page_content', '').lower()

        # SQL Injection: 높은 가중치
        if "SQL" in query or "sql" in query:
            for kw in primary:
                if kw.lower() in content:
                    score += 0.05  # 0.03 → 0.05 (개선)
        else:
            # 나머지 취약점
            for kw in primary:
                if kw.lower() in content:
                    score += 0.03

        # 보조 키워드 매칭
        for kw in secondary:
            if kw.lower() in content:
                score += 0.01

        # 코드 스니펫 탐지 (개선: 추가됨)
        code_indicators = ["def ", "import ", "class ", "try:", "except:", "cursor", "sql_query", "for ", "if "]
        code_match_count = sum(1 for code in code_indicators if code in content)
        if code_match_count >= 2:  # 코드 스니펫 확인
            score += 0.04  # 코드 우선순위

        # 언어 일치 보너스
        if language and result.payload.get('language') == language:
            score += 0.05

        # 높은 점수 문서 추가 보너스
        if result.score > 0.6:
            score += 0.02

        scored_results.append((score, result))

    scored_results.sort(key=lambda x: x[0], reverse=True)

    for score, result in scored_results:
        result.score = score

    return [r for _, r in scored_results]


def search_reference(query: str, language: str = None, top_k: int = 3, use_reranking: bool = True) -> list:
    """
    시큐어 코딩 레퍼런스 검색

    Args:
        query: 검색 쿼리
        language: 필터링 언어 ('java', 'python', None)
        top_k: 반환할 결과 개수
        use_reranking: 리랭킹 사용 여부
    """
    client = QdrantClient(url=QDRANT_URL, api_key=QDRANT_API_KEY, prefer_grpc=False)

    query_vector = EMBEDDING_MODEL.embed_query(query)

    fetch_k = top_k * 3 if use_reranking else top_k

    search_params = {
        "collection_name": COLLECTION_NAME,
        "query": query_vector,
        "limit": fetch_k
    }

    if language:
        search_params["query_filter"] = {
            "must": [
                {"key": "language", "match": {"value": language}}
            ]
        }

    response = client.query_points(**search_params)

    results = []
    for point in response.points:
        results.append({
            'similarity': round(point.score, 4),
            'language': point.payload.get('language'),
            'source': point.payload.get('source'),
            'page': point.payload.get('page'),
            'content': point.payload.get('page_content'),
            '_point': point
        })

    # 리랭킹 적용
    if use_reranking and results:
        class TempPoint:
            def __init__(self, d):
                self.score = d['similarity']
                self.payload = {
                    'page_content': d['content'],
                    'language': d['language']
                }

        temp_points = [TempPoint(r) for r in results]
        reranked = rerank_results(temp_points, query, language)

        for idx, point in enumerate(reranked):
            if idx < len(results):
                results[idx]['similarity'] = round(point.score, 4)

        results.sort(key=lambda x: x['similarity'], reverse=True)

    return results[:top_k]


def print_reference(query: str, language: str = None, top_k: int = 3, use_reranking: bool = True):
    """포맷된 레퍼런스 출력"""
    print(f"\n🔍 검색: {query}")
    if language:
        print(f"📌 언어: {language}")
    if use_reranking:
        print("🔄 리랭킹: 활성화")
    print("=" * 100)

    results = search_reference(query, language, top_k, use_reranking)

    if not results:
        print("❌ 검색 결과 없음")
        return

    for idx, r in enumerate(results, 1):
        print(f"\n[{idx}] 유사도: {r['similarity']} | {r['language'].upper()} | {r['source']} (page {r['page']})")
        print("-" * 100)
        print(r['content'][:1500])
        print()


if __name__ == "__main__":
    print("=" * 100)
    print("💻 시큐어 코딩 레퍼런스 (개선된 리랭킹)")
    print("=" * 100)

    # SQL Injection
    print_reference("SQL Injection 방지", language="java", top_k=2)

    # Python 쿼리 안전성
    print_reference("Python 데이터베이스 쿼리 안전성", language="python", top_k=2)

    # XSS
    print_reference("XSS 방어 필터링", top_k=2)

    # 명령어 삽입
    print_reference("OS Command Injection 방지", top_k=2)

    # 파일 업로드
    print_reference("파일 업로드 검증", top_k=2)

    # 세션 관리
    print_reference("세션 데이터 보안", top_k=2)

    print("=" * 100)
    print("✅ 완료")
    print("=" * 100)
