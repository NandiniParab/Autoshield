from pathlib import Path
from typing import Any, Dict, List, Optional
import os
from urllib.parse import quote

import requests


IMAGE_EXTENSIONS = {".jpg", ".jpeg", ".png", ".webp", ".bmp", ".gif"}

RISKY_DOMAINS = [
    "shutterstock",
    "gettyimages",
    "istockphoto",
    "alamy",
    "adobe",
    "stock",
    "dreamstime",
    "depositphotos",
    "freepik",
    "pinterest",
    "imdb",
    "netflix",
    "unsplash",
    "pexels",
]


class MediaReverseSearchScanner:
    def scan_project(
        self,
        project_path: str,
        public_base_url: Optional[str] = None,
        enable_reverse_search: bool = False,
        max_images: int = 5,
    ) -> Dict[str, Any]:
        root = Path(project_path)

        if not root.exists():
            return {
                "success": False,
                "error": "Project path does not exist",
                "issues": [],
            }

        images = self.find_images(root)[:max_images]
        issues: List[Dict[str, Any]] = []

        for image_path in images:
            issues.extend(self.local_checks(root, image_path))

            if enable_reverse_search:
                if not public_base_url:
                    issues.append(
                        {
                            "title": "Reverse image search skipped",
                            "severity": "LOW",
                            "category": "Reverse Image Search",
                            "file": str(image_path.relative_to(root)),
                            "evidence": "public_base_url was not provided.",
                            "recommendation": "Expose the image folder using ngrok and pass public_base_url.",
                        }
                    )
                else:
                    image_url = self.build_public_image_url(
                        root=root,
                        image_path=image_path,
                        public_base_url=public_base_url,
                    )
                    issues.extend(self.serpapi_google_lens(root, image_path, image_url))

        score = self.calculate_score(issues)

        return {
            "success": True,
            "category": "Media Copyright Risk / License Compliance",
            "project_path": str(root),
            "images_scanned": len(images),
            "reverse_search_enabled": enable_reverse_search,
            "compliance_score": score,
            "risk_level": self.get_risk_level(score),
            "issues": issues,
            "limitations": [
                "This module flags copyright/media licensing risk only.",
                "It does not legally prove copyright infringement.",
                "Manual license verification is required.",
            ],
        }

    def find_images(self, root: Path) -> List[Path]:
        ignored_dirs = {
            "node_modules",
            ".git",
            ".venv",
            "venv",
            "dist",
            "build",
            "__pycache__",
        }

        images: List[Path] = []

        for path in root.rglob("*"):
            if any(part in ignored_dirs for part in path.parts):
                continue

            if path.is_file() and path.suffix.lower() in IMAGE_EXTENSIONS:
                images.append(path)

        return images

    def local_checks(self, root: Path, image_path: Path) -> List[Dict[str, Any]]:
        issues = []
        rel = str(image_path.relative_to(root))
        lower_name = image_path.name.lower()

        if any(domain in lower_name for domain in RISKY_DOMAINS):
            issues.append(
                {
                    "title": "Image filename suggests stock/media source",
                    "severity": "HIGH",
                    "category": "Media Source Risk",
                    "file": rel,
                    "evidence": f"Filename contains risky media keyword: {image_path.name}",
                    "recommendation": "Verify purchase/license and store proof of rights.",
                }
            )

        return issues

    def build_public_image_url(
        self,
        root: Path,
        image_path: Path,
        public_base_url: str,
    ) -> str:
        rel = image_path.relative_to(root).as_posix()
        return public_base_url.rstrip("/") + "/" + quote(rel)

    def serpapi_google_lens(
        self,
        root: Path,
        image_path: Path,
        image_url: str,
    ) -> List[Dict[str, Any]]:
        rel = str(image_path.relative_to(root))
        api_key = os.getenv("SERPAPI_API_KEY")

        if not api_key:
            return [
                {
                    "title": "SerpAPI key missing",
                    "severity": "LOW",
                    "category": "Reverse Image Search",
                    "file": rel,
                    "evidence": "SERPAPI_API_KEY environment variable is not set.",
                    "recommendation": "Set SERPAPI_API_KEY in PowerShell.",
                }
            ]

        try:
            params = {
                "engine": "google_lens",
                "url": image_url,
                "api_key": api_key,
            }

            response = requests.get(
                "https://serpapi.com/search.json",
                params=params,
                timeout=30,
            )

            data = response.json()

            if response.status_code != 200:
                return [
                    {
                        "title": "SerpAPI reverse image search failed",
                        "severity": "LOW",
                        "category": "Reverse Image Search",
                        "file": rel,
                        "evidence": data,
                        "recommendation": "Check API key, quota, and image URL accessibility.",
                    }
                ]

            visual_matches = data.get("visual_matches", []) or []
            exact_matches = data.get("exact_matches", []) or []

            urls = []

            for item in exact_matches:
                link = item.get("link") or item.get("source")
                if link:
                    urls.append(link)

            for item in visual_matches:
                link = item.get("link") or item.get("source")
                if link:
                    urls.append(link)

            risky_urls = [
                url
                for url in urls
                if any(domain in url.lower() for domain in RISKY_DOMAINS)
            ]

            issues = []

            if urls:
                issues.append(
                    {
                        "title": "Image appears elsewhere on the web",
                        "severity": "MEDIUM",
                        "category": "Reverse Image Match",
                        "file": rel,
                        "evidence": f"SerpAPI Google Lens found {len(urls)} matching or visually similar results.",
                        "matches": urls[:10],
                        "recommendation": "Manually verify ownership, license, or attribution.",
                    }
                )

            if risky_urls:
                issues.append(
                    {
                        "title": "Image may match stock/media website",
                        "severity": "HIGH",
                        "category": "Stock Media Risk",
                        "file": rel,
                        "evidence": "Matching URLs include known stock/media/platform domains.",
                        "matches": risky_urls[:10],
                        "recommendation": "Verify purchase/license or replace with original media.",
                    }
                )

            return issues

        except Exception as e:
            return [
                {
                    "title": "Reverse image search unavailable",
                    "severity": "LOW",
                    "category": "Reverse Image Search",
                    "file": rel,
                    "evidence": str(e),
                    "recommendation": "Check internet connection, SerpAPI key, and public image URL.",
                }
            ]

    def scan_live_media_urls(
        self,
        page_url: str,
        image_urls: List[str],
        enable_reverse_search: bool = True,
        max_images: int = 5,
    ) -> Dict[str, Any]:
        issues: List[Dict[str, Any]] = []
        clean_urls: List[str] = []

        for url in image_urls:
            if not url:
                continue

            if url.startswith("data:") or url.startswith("blob:"):
                continue

            if url not in clean_urls:
                clean_urls.append(url)

        selected_urls = clean_urls[:max_images]

        for image_url in selected_urls:
            issues.extend(self.local_url_checks(image_url))

            if enable_reverse_search:
                issues.extend(self.serpapi_google_lens_url(image_url=image_url))

        score = self.calculate_score(issues)

        return {
            "success": True,
            "category": "Live Website Media Copyright Risk / License Compliance",
            "page_url": page_url,
            "images_scanned": len(selected_urls),
            "reverse_search_enabled": enable_reverse_search,
            "compliance_score": score,
            "risk_level": self.get_risk_level(score),
            "issues": issues,
            "limitations": [
                "This module flags copyright/media licensing risk only.",
                "It does not legally prove copyright infringement.",
                "Manual license verification is required.",
                "Data/blob images are skipped because they cannot be reverse-searched by URL.",
            ],
        }

    def local_url_checks(self, image_url: str) -> List[Dict[str, Any]]:
        issues = []
        lower_url = image_url.lower()

        if any(domain in lower_url for domain in RISKY_DOMAINS):
            issues.append(
                {
                    "title": "Image URL suggests stock/media source",
                    "severity": "HIGH",
                    "category": "Media Source Risk",
                    "file": image_url,
                    "evidence": f"Image URL contains known stock/media keyword: {image_url}",
                    "recommendation": "Verify purchase/license and store proof of rights.",
                }
            )

        return issues

    def serpapi_google_lens_url(self, image_url: str) -> List[Dict[str, Any]]:
        api_key = os.getenv("SERPAPI_API_KEY")

        if not api_key:
            return [
                {
                    "title": "SerpAPI key missing",
                    "severity": "LOW",
                    "category": "Reverse Image Search",
                    "file": image_url,
                    "evidence": "SERPAPI_API_KEY environment variable is not set.",
                    "recommendation": "Set SERPAPI_API_KEY in PowerShell before starting backend.",
                }
            ]

        try:
            params = {
                "engine": "google_lens",
                "url": image_url,
                "api_key": api_key,
            }

            response = requests.get(
                "https://serpapi.com/search.json",
                params=params,
                timeout=30,
            )

            data = response.json()

            if response.status_code != 200:
                return [
                    {
                        "title": "SerpAPI reverse image search failed",
                        "severity": "LOW",
                        "category": "Reverse Image Search",
                        "file": image_url,
                        "evidence": data,
                        "recommendation": "Check API key, quota, and image URL accessibility.",
                    }
                ]

            visual_matches = data.get("visual_matches", []) or []
            exact_matches = data.get("exact_matches", []) or []

            urls = []

            for item in exact_matches:
                link = item.get("link") or item.get("source")
                if link:
                    urls.append(link)

            for item in visual_matches:
                link = item.get("link") or item.get("source")
                if link:
                    urls.append(link)

            risky_urls = [
                url
                for url in urls
                if any(domain in url.lower() for domain in RISKY_DOMAINS)
            ]

            issues = []

            if urls:
                issues.append(
                    {
                        "title": "Image appears elsewhere on the web",
                        "severity": "MEDIUM",
                        "category": "Reverse Image Match",
                        "file": image_url,
                        "evidence": f"SerpAPI Google Lens found {len(urls)} matching or visually similar results.",
                        "matches": urls[:10],
                        "recommendation": "Manually verify ownership, license, or attribution.",
                    }
                )

            if risky_urls:
                issues.append(
                    {
                        "title": "Image may match stock/media website",
                        "severity": "HIGH",
                        "category": "Stock Media Risk",
                        "file": image_url,
                        "evidence": "Matching URLs include known stock/media/platform domains.",
                        "matches": risky_urls[:10],
                        "recommendation": "Verify purchase/license or replace with original media.",
                    }
                )

            return issues

        except Exception as e:
            return [
                {
                    "title": "Reverse image search unavailable",
                    "severity": "LOW",
                    "category": "Reverse Image Search",
                    "file": image_url,
                    "evidence": str(e),
                    "recommendation": "Check internet connection, SerpAPI key, and image URL.",
                }
            ]

    def calculate_score(self, issues: List[Dict[str, Any]]) -> int:
        score = 100

        for issue in issues:
            severity = issue.get("severity", "").upper()

            if severity == "HIGH":
                score -= 20
            elif severity == "MEDIUM":
                score -= 10
            elif severity == "LOW":
                score -= 3

        return max(score, 0)

    def get_risk_level(self, score: int) -> str:
        if score >= 85:
            return "LOW"
        if score >= 60:
            return "MEDIUM"
        if score >= 35:
            return "HIGH"
        return "CRITICAL"
