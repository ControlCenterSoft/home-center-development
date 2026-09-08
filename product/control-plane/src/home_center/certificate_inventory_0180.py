"""Secret-free certificate inventory and batch renewal planning."""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from enum import StrEnum
ID=re.compile(r"^[a-z][a-z0-9_.:-]{1,127}$"); FP=re.compile(r"^[0-9a-f]{64}$")
class CertificateInventoryError(ValueError):
    def __init__(self,code:str)->None: super().__init__(code); self.code=code
class CertificateState(StrEnum): VALID="valid"; EXPIRING="expiring"; EXPIRED="expired"; INVALID="invalid"
@dataclass(frozen=True,slots=True)
class CertificateInventoryRecord:
    certificate_id:str; service_id:str; issuer_id:str; fingerprint_sha256:str; not_before:datetime; not_after:datetime; chain_valid:bool; name_valid:bool; renewable:bool
    def __post_init__(self)->None:
        if any(ID.fullmatch(v) is None for v in (self.certificate_id,self.service_id,self.issuer_id)): raise CertificateInventoryError("invalid_identity")
        if FP.fullmatch(self.fingerprint_sha256) is None: raise CertificateInventoryError("invalid_fingerprint")
        if self.not_before.tzinfo is None or self.not_after.tzinfo is None or self.not_after<=self.not_before: raise CertificateInventoryError("invalid_validity_window")
    def state_at(self,now:datetime,warning_days:int=30)->CertificateState:
        if now.tzinfo is None: raise CertificateInventoryError("timezone_required")
        if not self.chain_valid or not self.name_valid: return CertificateState.INVALID
        if self.not_after<=now: return CertificateState.EXPIRED
        if self.not_after<=now+timedelta(days=warning_days): return CertificateState.EXPIRING
        return CertificateState.VALID
@dataclass(frozen=True,slots=True)
class CertificateInventory:
    observed_at:datetime; records:tuple[CertificateInventoryRecord,...]; production_mutation_enabled:bool=False; schema:str=field(default="home-center.certificate-inventory.v1",init=False)
    def __post_init__(self)->None:
        if self.observed_at.tzinfo is None: raise CertificateInventoryError("timezone_required")
        if len({r.certificate_id for r in self.records})!=len(self.records): raise CertificateInventoryError("duplicate_certificate_id")
@dataclass(frozen=True,slots=True)
class RenewalBatchItem:
    certificate_id:str; service_id:str; state:CertificateState; action:str; blockers:tuple[str,...]
@dataclass(frozen=True,slots=True)
class CertificateRenewalBatch:
    batch_id:str; state:str; items:tuple[RenewalBatchItem,...]; blockers:tuple[str,...]; production_mutation_enabled:bool=False; schema:str=field(default="home-center.certificate-renewal-batch.v1",init=False)
class CertificateInventoryPlanner:
    def plan_batch(self,inventory:CertificateInventory,*,batch_id:str,issuer_availability:dict[str,bool],reload_support:dict[str,bool],warning_days:int=30)->CertificateRenewalBatch:
        if ID.fullmatch(batch_id) is None: raise CertificateInventoryError("invalid_batch_id")
        items=[]; batch_blockers=[]
        for record in inventory.records:
            state=record.state_at(inventory.observed_at,warning_days); blockers=[]
            if state is CertificateState.VALID: continue
            if not record.renewable: blockers.append("certificate_not_renewable")
            if not issuer_availability.get(record.issuer_id,False): blockers.append("issuer_unavailable")
            if not reload_support.get(record.service_id,False): blockers.append("service_reload_unsupported")
            if state is CertificateState.INVALID: blockers.append("certificate_identity_invalid")
            items.append(RenewalBatchItem(record.certificate_id,record.service_id,state,"renew",tuple(blockers)))
            if blockers: batch_blockers.append(f"blocked:{record.certificate_id}")
        return CertificateRenewalBatch(batch_id,"blocked" if batch_blockers else "planned",tuple(items),tuple(batch_blockers))
