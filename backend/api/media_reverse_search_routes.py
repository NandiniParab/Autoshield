from typing import List, Optional

from fastapi import APIRouter
from pydantic import BaseModel

from compliance.media_reverse_search_scanner import MediaReverseSearchScanner


router = APIRouter()


class MediaReverseSearchRequest(BaseModel):
    project_path: str
    public_base_url: Optional[str] = None
    enable_reverse_search: Optional[bool] = False
    max_images: Optional[int] = 5


class LiveMediaComplianceRequest(BaseModel):
    page_url: str
    image_urls: List[str]
    enable_reverse_search: Optional[bool] = True
    max_images: Optional[int] = 5


@router.post("/media-license/scan")
def scan_media_license(request: MediaReverseSearchRequest):
    scanner = MediaReverseSearchScanner()

    return scanner.scan_project(
        project_path=request.project_path,
        public_base_url=request.public_base_url,
        enable_reverse_search=request.enable_reverse_search or False,
        max_images=request.max_images or 5,
    )


@router.post("/media-license/scan-live")
def scan_live_media_license(request: LiveMediaComplianceRequest):
    scanner = MediaReverseSearchScanner()

    return scanner.scan_live_media_urls(
        page_url=request.page_url,
        image_urls=request.image_urls,
        enable_reverse_search=(
            request.enable_reverse_search
            if request.enable_reverse_search is not None
            else True
        ),
        max_images=request.max_images or 5,
    )
