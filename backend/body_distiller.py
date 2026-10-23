"""
Proxsynth - LLM Semantic Response Body Distiller
Reduces multi-megabyte HTML and massive JSON API responses into high-density,
security-focused structural representations. Strips styling, SVG assets, base64 blobs,
and noise to reduce LLM context token usage by 85-95% while highlighting forms,
inputs, API endpoints, reflections, and sensitive parameters.
"""

import re
import json
import urllib.parse
from html.parser import HTMLParser
from typing import Dict, Any, List, Optional, Set, Tuple


class HTMLSecurityDistiller(HTMLParser):
    def __init__(self, reflected_query: Optional[str] = None):
        super().__init__()
        self.reflected_query = reflected_query.strip() if reflected_query else None
        self.title = ""
        self.in_title = False
        self.in_script = False
        self.in_style = False
        
        self.forms: List[Dict[str, Any]] = []
        self.current_form: Optional[Dict[str, Any]] = None
        self.endpoints: Set[str] = set()
        self.comments: List[str] = []
        self.buttons: List[str] = []
        self.reflected_locations: List[Dict[str, Any]] = []
        self.sensitive_findings: List[str] = []

    def handle_starttag(self, tag: str, attrs: List[Tuple[str, Optional[str]]]):
        attr_dict = {k.lower(): (v or "") for k, v in attrs}
        
        # Check reflections in tag attributes
        if self.reflected_query:
            for k, v in attr_dict.items():
                if self.reflected_query.lower() in v.lower():
                    self.reflected_locations.append({
                        "context": f"attribute_{tag}_{k}",
                        "tag": tag,
                        "attr": k,
                        "value": v[:150]
                    })

        if tag == "title":
            self.in_title = True
        elif tag == "script":
            self.in_script = True
            src = attr_dict.get("src")
            if src and not src.startswith("data:"):
                self.endpoints.add(src)
        elif tag == "style":
            self.in_style = True
        elif tag == "form":
            action = attr_dict.get("action", "")
            method = attr_dict.get("method", "GET").upper()
            self.current_form = {
                "action": action,
                "method": method,
                "inputs": []
            }
            if action:
                self.endpoints.add(action)
        elif tag in ("input", "textarea", "select"):
            name = attr_dict.get("name", "")
            inp_type = attr_dict.get("type", "text")
            value = attr_dict.get("value", "")
            if name or inp_type:
                inp_desc = {
                    "name": name,
                    "type": inp_type,
                    "value": value[:100] if value else ""
                }
                if self.current_form is not None:
                    self.current_form["inputs"].append(inp_desc)
                else:
                    # Standalone input
                    self.forms.append({
                        "action": "[standalone_input]",
                        "method": "FORMLESS",
                        "inputs": [inp_desc]
                    })
        elif tag == "button":
            btn_text = attr_dict.get("name") or attr_dict.get("id") or attr_dict.get("type", "button")
            self.buttons.append(btn_text)
        elif tag == "a":
            href = attr_dict.get("href", "")
            if href and not href.startswith(("#", "javascript:", "mailto:", "tel:")):
                # Retain API endpoints or paths with query parameters
                if any(k in href for k in ["/api", "?", "=", ".php", ".json", ".action", "/admin", "/user"]):
                    self.endpoints.add(href)

    def handle_endtag(self, tag: str):
        if tag == "title":
            self.in_title = False
        elif tag == "script":
            self.in_script = False
        elif tag == "style":
            self.in_style = False
        elif tag == "form":
            if self.current_form:
                self.forms.append(self.current_form)
                self.current_form = None

    def handle_data(self, data: str):
        if self.in_title:
            self.title = (self.title + " " + data.strip()).strip()
        elif self.in_script:
            # Extract inline API routes or fetch/axios calls
            for match in re.findall(r"""['"`](\/(?:api|v[0-9]+|graphql|auth|admin)[a-zA-Z0-9_\-\.\/\?=&]*)['"`]""", data):
                self.endpoints.add(match)
        
        # Check text reflection
        if self.reflected_query and not self.in_style and not self.in_script:
            if self.reflected_query.lower() in data.lower():
                self.reflected_locations.append({
                    "context": "html_body_text",
                    "snippet": data.strip()[:200]
                })

    def handle_comment(self, data: str):
        clean_comment = data.strip()
        if clean_comment and len(clean_comment) > 3:
            # Check for secrets, endpoints, or dev notes in comments
            lower_c = clean_comment.lower()
            if any(k in lower_c for k in ["todo", "fixme", "password", "key", "admin", "token", "api", "secret", "user", "internal"]):
                self.comments.append(clean_comment[:300])


def _summarize_json_structure(data: Any, depth: int = 0, max_depth: int = 4) -> Any:
    """Summarizes deep JSON trees into a compact schema without thousands of repetitive array entries."""
    if depth > max_depth:
        return "...[truncated depth]"

    if isinstance(data, dict):
        summary = {}
        for k, v in data.items():
            k_lower = str(k).lower()
            is_sensitive = any(s in k_lower for s in ["id", "token", "secret", "password", "key", "admin", "role", "email", "auth", "hash"])
            if is_sensitive and isinstance(v, (str, int, float, bool)):
                summary[k] = f"{v} (high-value identifier)"
            elif isinstance(v, (dict, list)):
                summary[k] = _summarize_json_structure(v, depth + 1, max_depth)
            else:
                summary[k] = type(v).__name__
        return summary
    elif isinstance(data, list):
        if not data:
            return []
        sample = [_summarize_json_structure(data[0], depth + 1, max_depth)]
        if len(data) > 1:
            sample.append(f"... +{len(data) - 1} more items of same type")
        return sample
    return type(data).__name__


def distill_response_body(
    body: str,
    content_type: str = "text/html",
    max_length: int = 4000,
    reflected_query: Optional[str] = None
) -> Dict[str, Any]:
    """
    Distills raw HTTP response bodies into compact, high-density security summaries.
    Saves LLM token consumption while highlighting high-impact attack surfaces.
    """
    if not body:
        return {
            "content_type": "empty",
            "original_size": 0,
            "distilled_size": 0,
            "token_reduction_percent": 0.0,
            "compact_summary": "[Empty Response Body]"
        }

    orig_size = len(body)
    ct_lower = (content_type or "").lower()

    # 1. JSON API Distillation
    if "application/json" in ct_lower or (body.strip().startswith(("{", "[")) and body.strip().endswith(("}", "]"))):
        try:
            parsed_json = json.loads(body)
            schema_summary = _summarize_json_structure(parsed_json)
            compact_json_str = json.dumps(schema_summary, indent=2)
            
            # Find high-value extracted identifiers
            sensitive_keys = []
            flat_str = body[:50000].lower()
            for kw in ["jwt", "bearer", "apikey", "secret", "private_key", "password", "admin"]:
                if kw in flat_str:
                    sensitive_keys.append(kw)

            markdown_summary = f"### [Distilled JSON API Response]\n```json\n{compact_json_str[:max_length]}\n```"
            if sensitive_keys:
                markdown_summary += f"\n**High-Value Keys Detected**: {', '.join(sorted(list(set(sensitive_keys))))}"

            dist_size = len(markdown_summary)
            reduction = max(0.0, round(((orig_size - dist_size) / orig_size) * 100, 1))

            return {
                "content_type": "json",
                "original_size": orig_size,
                "distilled_size": dist_size,
                "token_reduction_percent": reduction,
                "stats": {
                    "original_bytes": orig_size,
                    "distilled_bytes": dist_size,
                    "token_reduction_pct": f"{reduction}%"
                },
                "forms": [],
                "api_endpoints": [],
                "schema_summary": schema_summary,
                "sensitive_indicators": sorted(list(set(sensitive_keys))),
                "compact_summary": markdown_summary
            }
        except Exception:
            pass

    # 2. HTML Webpage Distillation
    parser = HTMLSecurityDistiller(reflected_query=reflected_query)
    try:
        parser.feed(body)
    except Exception:
        pass

    lines = ["### [Distilled Security View: HTML DOM]"]
    if parser.title:
        lines.append(f"**Page Title**: {parser.title}")

    # Forms & Input Attack Surface
    if parser.forms:
        lines.append(f"\n**Interactive Forms ({len(parser.forms)})**:")
        for idx, f in enumerate(parser.forms[:10]):
            action = f.get("action") or "[self]"
            method = f.get("method") or "GET"
            inputs_str = ", ".join([f"{i.get('name') or '[unnamed]'} ({i.get('type')})" for i in f.get("inputs", [])])
            lines.append(f"- Form #{idx + 1}: `{method} {action}` | Inputs: [{inputs_str or 'None'}]")

    # API Endpoints
    if parser.endpoints:
        lines.append(f"\n**Discovered API Endpoints & Links ({len(parser.endpoints)})**:")
        for ep in sorted(list(parser.endpoints))[:15]:
            lines.append(f"- `{ep}`")

    # Reflected Contexts (XSS / Parameter Reflection)
    if parser.reflected_locations:
        lines.append(f"\n**Payload Reflections Detected ({len(parser.reflected_locations)})**:")
        for ref in parser.reflected_locations[:5]:
            ctx = ref.get("context")
            val = ref.get("value") or ref.get("snippet") or ""
            lines.append(f"- Context `{ctx}`: `{val}`")

    # Sensitive HTML Comments
    if parser.comments:
        lines.append(f"\n**Sensitive Developer Comments ({len(parser.comments)})**:")
        for c in parser.comments[:5]:
            lines.append(f"- `<!-- {c} -->`")

    compact_html_str = "\n".join(lines)
    dist_size = len(compact_html_str)
    reduction = max(0.0, round(((orig_size - dist_size) / orig_size) * 100, 1)) if orig_size > dist_size else 0.0

    return {
        "content_type": "html",
        "original_size": orig_size,
        "distilled_size": dist_size,
        "token_reduction_percent": reduction,
        "stats": {
            "original_bytes": orig_size,
            "distilled_bytes": dist_size,
            "token_reduction_pct": f"{reduction}%"
        },
        "forms_count": len(parser.forms),
        "forms": parser.forms,
        "endpoints_count": len(parser.endpoints),
        "api_endpoints": sorted(list(parser.endpoints)),
        "reflections": parser.reflected_locations,
        "comments": parser.comments,
        "compact_summary": compact_html_str
    }
