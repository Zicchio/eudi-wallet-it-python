# generated by datamodel-codegen:
#   filename:  https://raw.githubusercontent.com/openid/oid4vc-haip-sd-jwt-vc/main/schemas/presentation_definition.json
#   timestamp: 2023-12-05T14:15:47+00:00

from __future__ import annotations

from enum import Enum
from typing import Annotated, Any, Dict, List, Optional, Union

from pydantic import BaseModel, ConfigDict, Field, RootModel, conint


class LimitDisclosure(Enum):
    required = "required"
    preferred = "preferred"


class Constraints(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    limit_disclosure: Optional[LimitDisclosure] = None
    fields: Optional[List[Any]] = None


class PresentationDefinitionClaimFormatDesignations1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    alg: Optional[List[str]] = Field(None, min_length=1)


class PresentationDefinitionClaimFormatDesignations2(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    proof_type: Optional[List[str]] = Field(None, min_length=1)


class PresentationDefinitionClaimFormatDesignations3(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )


class PresentationDefinitionClaimFormatDesignations(
    RootModel[
        Union[
            Dict[
                Annotated[str, Field(pattern=r"^jwt$|^jwt_vc$|^jwt_vp$")],
                PresentationDefinitionClaimFormatDesignations1,
            ],
            Dict[
                Annotated[str, Field(pattern=r"^ldp_vc$|^ldp_vp$|^ldp$")],
                PresentationDefinitionClaimFormatDesignations2,
            ],
            Dict[
                Annotated[str, Field(pattern=r"^dc\+sd-jwt$")],
                PresentationDefinitionClaimFormatDesignations3,
            ],
        ]
    ]
):
    root: Union[
        Dict[
            Annotated[str, Field(pattern=r"^jwt$|^jwt_vc$|^jwt_vp$")],
            PresentationDefinitionClaimFormatDesignations1,
        ],
        Dict[
            Annotated[str, Field(pattern=r"^ldp_vc$|^ldp_vp$|^ldp$")],
            PresentationDefinitionClaimFormatDesignations2,
        ],
        Dict[
            Annotated[str, Field(pattern=r"^dc\+sd-jwt$")],
            PresentationDefinitionClaimFormatDesignations2,
        ],
    ] = Field(..., title="Presentation Definition Claim Format Designations")


class Rule(Enum):
    pick = "pick"


class SubmissionRequirement1(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    name: Optional[str] = None
    rule: Rule
    count: Optional[conint(ge=1)] = None
    from_: str = Field(..., alias="from")


class SubmissionRequirement(RootModel[SubmissionRequirement1]):
    root: SubmissionRequirement1


class InputDescriptor(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    id: str
    name: Optional[str] = None
    purpose: Optional[str] = None
    format: Optional[PresentationDefinitionClaimFormatDesignations] = None
    group: Optional[List[str]] = None
    constraints: Constraints


class PresentationDefinition(BaseModel):
    model_config = ConfigDict(
        extra="forbid",
    )
    id: str
    input_descriptors: List[InputDescriptor]
    submission_requirements: Optional[List[SubmissionRequirement]] = None
