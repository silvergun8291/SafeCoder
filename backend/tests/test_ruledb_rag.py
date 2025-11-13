from qdrant_client import QdrantClient
from qdrant_client.models import Filter, FieldCondition, MatchText
client = QdrantClient(url="http://localhost:6333")  # 설정에 맞게 변경
# 총 개수
print(client.count(collection_name="semgrep_rule_db", exact=True).count)
# autofix.md 존재 확인
flt = Filter(must=[FieldCondition(key="source", match=MatchText(text="autofix.md"))])
points, _ = client.scroll(collection_name="semgrep_rule_db", scroll_filter=flt, with_payload=True, limit=3)
print(len(points), [p.payload.get("source") for p in points])