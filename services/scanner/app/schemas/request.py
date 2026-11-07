from pydantic import BaseModel, Field


class AnalysisRequest(BaseModel):
    url: str = Field(..., min_length=1, max_length=2048, description="Target URL to inspect")
    scanId: str = Field(..., min_length=1, description="Database scan document ID")
    normalizedDomain: str = Field(..., min_length=1, description="Target normalized hostname")
    deepScan: bool = Field(default=False, description="Whether to perform intensive deep inspections")
