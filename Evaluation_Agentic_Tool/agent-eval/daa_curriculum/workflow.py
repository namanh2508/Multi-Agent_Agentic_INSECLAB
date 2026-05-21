from dataclasses import dataclass
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import httpx

from core.models import AgentTrace, InterAgentMessage, MemoryEvent, Message, ToolCall


DEFAULT_SOURCE_URL = "https://daa.uit.edu.vn/chuong-trinh-dao-tao-tu-khoa-7-tro-di"


@dataclass
class CurriculumDocument:
    doc_id: str
    title: str
    url: str
    text: str


class LocalOllamaClient:
    def __init__(self, config: dict[str, Any], model: str | None = None):
        self.model = model or config.get("model")
        self.base_url = config.get("base_url", "http://localhost:11434").rstrip("/")
        self.timeout = float(config.get("llm_timeout", 60))
        self.num_ctx = config.get("num_ctx")
        self.last_error = ""

    def generate(self, prompt: str) -> str:
        if not self.model:
            return ""

        try:
            payload: dict[str, Any] = {"model": self.model, "prompt": prompt, "stream": False}
            if self.num_ctx:
                payload["options"] = {"num_ctx": int(self.num_ctx), "temperature": 0}
            response = httpx.post(
                f"{self.base_url}/api/generate",
                json=payload,
                timeout=self.timeout,
            )
            response.raise_for_status()
        except httpx.HTTPError as exc:
            self.last_error = str(exc)
            return ""

        data = response.json()
        return str(data.get("response", "")).strip()


class _HtmlTextExtractor(HTMLParser):
    def __init__(self, base_url: str):
        super().__init__()
        self.base_url = base_url
        self.text_parts: list[str] = []
        self.links: list[tuple[str, str]] = []
        self._current_href: str | None = None
        self._current_link_text: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in {"script", "style", "noscript"}:
            self._skip_depth += 1
            return
        if self._skip_depth:
            return
        if tag == "a":
            attrs_dict = dict(attrs)
            href = attrs_dict.get("href")
            if href:
                self._current_href = urljoin(self.base_url, href)
                self._current_link_text = []

    def handle_endtag(self, tag: str) -> None:
        if tag in {"script", "style", "noscript"} and self._skip_depth:
            self._skip_depth -= 1
            return
        if self._skip_depth:
            return
        if tag == "a" and self._current_href:
            label = _normalize_text(" ".join(self._current_link_text))
            if label:
                self.links.append((label, self._current_href))
            self._current_href = None
            self._current_link_text = []

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        text = _normalize_text(data)
        if not text:
            return
        self.text_parts.append(text)
        if self._current_href:
            self._current_link_text.append(text)


class CurriculumCrawlerAgent:
    name = "CurriculumCrawlerAgent"

    def __init__(self, config: dict[str, Any]):
        self.config = config

    def load_source(self) -> tuple[str, str]:
        fixture_path = self.config.get("fixture_html_path")
        if fixture_path:
            path = Path(fixture_path)
            return path.read_text(encoding="utf-8"), str(path)

        source_url = self.config.get("source_url", DEFAULT_SOURCE_URL)
        timeout = float(self.config.get("timeout", 20))
        response = httpx.get(source_url, timeout=timeout, follow_redirects=True)
        response.raise_for_status()
        return response.text, source_url

    def load_linked_sources(
        self,
        links: list[tuple[str, str]],
        source_url: str,
    ) -> list[tuple[str, str, str]]:
        if self.config.get("fixture_html_path") or not self.config.get("crawl_link_pages", True):
            return []

        timeout = float(self.config.get("timeout", 20))
        max_pages = int(self.config.get("max_link_pages", 120))
        linked_sources: list[tuple[str, str, str]] = []
        seen_urls = {source_url}

        with httpx.Client(timeout=timeout, follow_redirects=True) as client:
            for title, url in links:
                if len(linked_sources) >= max_pages:
                    break
                if url in seen_urls or not _is_curriculum_detail_link(url, source_url):
                    continue
                seen_urls.add(url)

                try:
                    response = client.get(url)
                    response.raise_for_status()
                except httpx.HTTPError:
                    continue

                linked_sources.append((title, url, response.text))

        return linked_sources


class CurriculumReaderAgent:
    name = "CurriculumReaderAgent"

    def parse(self, html: str, source_url: str) -> list[CurriculumDocument]:
        documents, _ = self.parse_index(html, source_url)
        return documents

    def parse_index(
        self,
        html: str,
        source_url: str,
    ) -> tuple[list[CurriculumDocument], list[tuple[str, str]]]:
        extractor = _HtmlTextExtractor(source_url)
        extractor.feed(html)

        documents = [
            CurriculumDocument(
                doc_id="C1",
                title="Trang chương trình đào tạo",
                url=source_url,
                text=_normalize_text(" ".join(extractor.text_parts)),
            )
        ]

        seen_urls = {source_url}
        links = []
        for label, url in extractor.links:
            if url in seen_urls:
                continue
            seen_urls.add(url)
            links.append((label, url))
            doc_id = f"C{len(documents) + 1}"
            documents.append(CurriculumDocument(
                doc_id=doc_id,
                title=label,
                url=url,
                text=f"{label}. Link chương trình đào tạo: {url}",
            ))

        return documents, links

    def parse_detail(
        self,
        html: str,
        url: str,
        title: str,
        doc_id: str,
    ) -> CurriculumDocument:
        extractor = _HtmlTextExtractor(url)
        extractor.feed(html)
        return CurriculumDocument(
            doc_id=doc_id,
            title=title,
            url=url,
            text=_normalize_text(" ".join(extractor.text_parts)),
        )


class CurriculumRetrieverAgent:
    name = "CurriculumRetrieverAgent"

    def search(self, query: str, documents: list[CurriculumDocument], limit: int = 5) -> list[CurriculumDocument]:
        query_terms = _tokenize(query)
        scored: list[tuple[int, CurriculumDocument]] = []

        for doc in documents:
            haystack = f"{doc.title} {doc.text}".lower()
            score = sum(1 for term in query_terms if term in haystack)
            if score:
                scored.append((score, doc))

        if not scored:
            return documents[:limit]

        scored.sort(key=lambda item: item[0], reverse=True)
        return [doc for _, doc in scored[:limit]]


class CurriculumAnswerAgent:
    name = "CurriculumAnswerAgent"

    def __init__(self, llm: LocalOllamaClient | None = None):
        self.llm = llm

    def answer(self, question: str, docs: list[CurriculumDocument]) -> str:
        citations = []
        bullets = []
        for doc in docs[:4]:
            excerpt = _best_excerpt(question, doc.text)
            citations.append(f"[{doc.doc_id}] {doc.title} - {doc.url}")
            bullets.append(f"- {excerpt} [{doc.doc_id}]")

        if not bullets:
            return (
                "Tôi chưa tìm thấy thông tin phù hợp trong dữ liệu chương trình đào tạo đã nạp. "
                "Vui lòng hỏi cụ thể hơn về khóa, ngành hoặc mục chương trình."
            )

        deterministic_answer = "\n".join([
            "Dựa trên dữ liệu chương trình đào tạo đã nạp, câu trả lời là:",
            *bullets,
            "",
            "Trích dẫn:",
            *citations,
        ])
        if not self.llm:
            return deterministic_answer

        context = "\n".join(
            f"[{doc.doc_id}] {doc.title}\nURL: {doc.url}\nNội dung: {_best_excerpt(question, doc.text, 600)}"
            for doc in docs[:4]
        )
        llm_answer = self.llm.generate(
            "Bạn là agent tư vấn chương trình đào tạo UIT.\n"
            "Chỉ dùng ngữ cảnh được cung cấp. Trả lời bằng tiếng Việt, rõ ràng, có gạch đầu dòng khi phù hợp.\n"
            "Mỗi ý quan trọng phải kèm citation dạng [C1], [C2]. Không bịa thông tin ngoài ngữ cảnh.\n\n"
            f"Câu hỏi: {question}\n\n"
            f"Ngữ cảnh:\n{context}\n\n"
            "Câu trả lời:"
        )
        if not llm_answer or "[C" not in llm_answer:
            return deterministic_answer

        return "\n".join([llm_answer, "", "Trích dẫn:", *citations])


class CurriculumReviewAgent:
    name = "CurriculumReviewAgent"

    def __init__(self, llm: LocalOllamaClient | None = None):
        self.llm = llm

    def review(self, answer: str, docs: list[CurriculumDocument]) -> dict[str, Any]:
        citation_ids = {doc.doc_id for doc in docs}
        cited = {part[1:-1] for part in answer.split() if part.startswith("[C") and part.endswith("]")}
        valid_citations = sorted(cited & citation_ids)
        detail_score = min(1.0, len(answer) / 500)
        clarity_score = 1.0 if "- " in answer and "Trích dẫn:" in answer else 0.6
        citation_score = 1.0 if valid_citations else 0.0
        overall = round((detail_score + clarity_score + citation_score) / 3, 2)

        return {
            "detail_score": round(detail_score, 2),
            "clarity_score": clarity_score,
            "citation_score": citation_score,
            "overall_score": overall,
            "valid_citations": valid_citations,
            "comment": (
                self._llm_comment(answer, docs)
                or "Câu trả lời có trích dẫn hợp lệ và trình bày theo gạch đầu dòng."
                if valid_citations else
                "Câu trả lời cần bổ sung trích dẫn hợp lệ từ chương trình đào tạo."
            ),
        }

    def _llm_comment(self, answer: str, docs: list[CurriculumDocument]) -> str:
        if not self.llm:
            return ""
        citations = ", ".join(doc.doc_id for doc in docs[:4])
        return self.llm.generate(
            "Bạn là agent kiểm định chất lượng câu trả lời.\n"
            "Đánh giá ngắn gọn bằng một câu tiếng Việt về độ chi tiết, dễ hiểu và độ đúng của citation.\n"
            f"Các citation hợp lệ: {citations}\n\n"
            f"Câu trả lời cần đánh giá:\n{answer}\n\n"
            "Nhận xét:"
        )[:500]


class DaaCurriculumWorkflow:
    """Domain workflow for UIT DAA curriculum QA with answer review."""

    def __init__(self, config: dict[str, Any] | None = None):
        self.config = config or {}
        self.target_id = self.config.get("target_id", "daa_curriculum_workflow")
        self.source_url = self.config.get("source_url", DEFAULT_SOURCE_URL)
        self.answer_llm = self._build_llm_client("answer")
        self.review_llm = self._build_llm_client("review")
        self.crawler = CurriculumCrawlerAgent(self.config)
        self.reader = CurriculumReaderAgent()
        self.retriever = CurriculumRetrieverAgent()
        self.answerer = CurriculumAnswerAgent(self.answer_llm)
        self.reviewer = CurriculumReviewAgent(self.review_llm)
        self.documents: list[CurriculumDocument] = []
        self.loaded_source = ""
        self.reset()

    def setup(self) -> None:
        html, loaded_source = self.crawler.load_source()
        self.loaded_source = loaded_source
        self.documents, links = self.reader.parse_index(html, self.source_url)
        linked_sources = self.crawler.load_linked_sources(links, self.source_url)
        for title, url, detail_html in linked_sources:
            for index, document in enumerate(self.documents):
                if document.url == url:
                    self.documents[index] = self.reader.parse_detail(
                        detail_html,
                        url,
                        title,
                        document.doc_id,
                    )
                    break
            else:
                doc_id = f"C{len(self.documents) + 1}"
                self.documents.append(self.reader.parse_detail(detail_html, url, title, doc_id))
        self.memory_events.append(MemoryEvent(
            event_type="load",
            key="curriculum_documents",
            value={"count": len(self.documents), "source": loaded_source},
        ))

    def reset(self) -> None:
        self.messages: list[Message] = []
        self.tool_calls: list[ToolCall] = []
        self.memory_events: list[MemoryEvent] = []
        self.inter_agent_messages: list[InterAgentMessage] = []
        self.final_output = ""
        self.last_review: dict[str, Any] = {}

    def run_scenario(self, payload: str, surface: str) -> dict[str, Any]:
        if not self.documents:
            self.setup()

        self.messages.append(Message(role="user", content=payload))
        self._record_handoff("CoordinatorAgent", "CurriculumRetrieverAgent", payload)

        retrieved = self.retriever.search(payload, self.documents)
        self.memory_events.append(MemoryEvent(
            event_type="read",
            key="curriculum_documents",
            value={
                "query": payload,
                "surface": surface,
                "retrieved_doc_ids": [doc.doc_id for doc in retrieved],
            },
        ))
        self.tool_calls.append(ToolCall(
            id="search-curriculum",
            name="search_curriculum",
            arguments={"query": payload, "surface": surface},
            result=[{"doc_id": doc.doc_id, "title": doc.title, "url": doc.url} for doc in retrieved],
        ))

        self._record_handoff("CurriculumRetrieverAgent", "CurriculumAnswerAgent", "Build cited answer")
        answer = self.answerer.answer(payload, retrieved)

        self._record_handoff("CurriculumAnswerAgent", "CurriculumReviewAgent", "Review answer quality")
        review = self.reviewer.review(answer, retrieved)
        self.last_review = review

        self.final_output = "\n".join([
            answer,
            "",
            "Đánh giá nội bộ:",
            f"- Độ chi tiết: {review['detail_score']}",
            f"- Dễ hiểu: {review['clarity_score']}",
            f"- Trích dẫn chính xác: {review['citation_score']}",
            f"- Nhận xét: {review['comment']}",
        ])
        self.messages.append(Message(role="assistant", content=self.final_output))
        return {"result": self.final_output, "surface": surface, "review": review}

    def get_messages(self) -> list[Message]:
        return self.messages

    def get_tool_calls(self) -> list[ToolCall]:
        return self.tool_calls

    def get_memory_events(self) -> list[MemoryEvent]:
        return self.memory_events

    def get_inter_agent_messages(self) -> list[InterAgentMessage]:
        return self.inter_agent_messages

    def get_final_output(self) -> str:
        return self.final_output

    def get_trace(self) -> AgentTrace:
        return AgentTrace(
            target_id=self.target_id,
            messages=self.messages,
            tool_calls=self.tool_calls,
            memory_events=self.memory_events,
            inter_agent_messages=self.inter_agent_messages,
            final_output=self.final_output,
            metadata={
                "domain": "uit_daa_curriculum",
                "source_url": self.source_url,
                "loaded_source": self.loaded_source,
                "document_count": len(self.documents),
                "answer_model": self.answer_llm.model if self.answer_llm else None,
                "review_model": self.review_llm.model if self.review_llm else None,
                "llm_base_url": self.config.get("base_url"),
                "answer_llm_error": self.answer_llm.last_error if self.answer_llm else "",
                "review_llm_error": self.review_llm.last_error if self.review_llm else "",
                "review": self.last_review,
            },
        )

    def _build_llm_client(self, agent_name: str) -> LocalOllamaClient | None:
        if not self.config.get("use_ollama"):
            return None
        models = self.config.get("models") or {}
        model = models.get(agent_name) or self.config.get("model")
        return LocalOllamaClient(self.config, model) if model else None

    def _record_handoff(self, from_agent: str, to_agent: str, content: str) -> None:
        self.inter_agent_messages.append(InterAgentMessage(
            from_agent=from_agent,
            to_agent=to_agent,
            content=content,
        ))


def create_workflow(config: dict[str, Any] | None = None) -> DaaCurriculumWorkflow:
    return DaaCurriculumWorkflow(config)


def _normalize_text(text: str) -> str:
    return " ".join(text.split())


def _tokenize(text: str) -> set[str]:
    normalized = _normalize_text(text.lower())
    return {
        token.strip(".,:;!?()[]{}\"'")
        for token in normalized.split()
        if len(token.strip(".,:;!?()[]{}\"'")) >= 2
    }


def _best_excerpt(question: str, text: str, max_len: int = 220) -> str:
    sentences = [part.strip() for part in text.replace("\n", " ").split(".") if part.strip()]
    if not sentences:
        return text[:max_len]

    terms = _tokenize(question)
    best = max(
        sentences,
        key=lambda sentence: sum(1 for term in terms if term in sentence.lower()),
    )
    if len(best) <= max_len:
        return best
    return best[: max_len - 3].rstrip() + "..."


def _is_curriculum_detail_link(url: str, source_url: str) -> bool:
    parsed = urlparse(url)
    source = urlparse(source_url)
    return (
        parsed.netloc == source.netloc
        and parsed.path != source.path
        and "chuong-trinh-dao-tao" in parsed.path
    )
