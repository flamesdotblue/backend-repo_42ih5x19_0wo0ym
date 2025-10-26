from typing import List, Optional, Annotated
from pydantic import BaseModel, Field, StringConstraints

# Reusable constrained types (Pydantic v2 style)
AyushId = Annotated[str, StringConstraints(min_length=6, max_length=32, pattern=r"^[A-Z0-9-]{6,32}$")]
RoleType = Annotated[str, StringConstraints(pattern=r"^(patient|practitioner)$")]
DocHash = Annotated[str, StringConstraints(min_length=32, max_length=128)]


class PractitionerVerifyRequest(BaseModel):
    ayush_id: AyushId
    name: Annotated[str, StringConstraints(min_length=2, max_length=80)]
    specialization: Optional[str] = None
    document_hash: DocHash = Field(
        ..., description="SHA-256 or similar hash of verification document"
    )


class PractitionerResponse(BaseModel):
    practitioner_id: str
    verified: bool
    credential_hash: str
    tx_hash: str


class ChatMessageCreate(BaseModel):
    patient_id: str
    practitioner_id: str
    role: RoleType
    content: Optional[str] = None
    attachments: Optional[List[str]] = []
    language: Optional[str] = "auto"


class ChatMessageResponse(BaseModel):
    id: str = Field(..., alias="_id")
    patient_id: str
    practitioner_id: str
    role: str
    content: Optional[str] = None
    attachments: Optional[List[str]] = []
    language: Optional[str] = "auto"
    created_at: Optional[str] = None

    class Config:
        populate_by_name = True


class ChatQuery(BaseModel):
    patient_id: str
    practitioner_id: str
    limit: int = 50


class DietPlanRequest(BaseModel):
    name: Optional[str] = None
    age: Optional[int] = None
    location: Optional[str] = None
    prakriti: Optional[str] = None
    lifestyle: Optional[str] = None
    preferences: Optional[str] = None


class DietPlan(BaseModel):
    summary: str
    diet: List[str]
    lifestyle: List[str]
    adjustments: str


class ConsultationSessionCreate(BaseModel):
    patient_id: str
    practitioner_id: str


class ConsultationSessionResponse(BaseModel):
    session_id: str
    token: str
    expires_in: int
