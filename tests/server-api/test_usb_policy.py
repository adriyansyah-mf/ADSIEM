"""Group policy usb_storage / usb_allow (services/agent_policy.py): audit by
default, allow entries normalised (hex upper case, serial as written,
duplicates dropped) and malformed ones refused."""
import pytest
from pydantic import ValidationError

from app.services.agent_policy import PolicySettings


def test_audit_by_default_and_nothing_allowed():
    s = PolicySettings()
    assert s.usb_storage == "audit" and s.usb_allow == []


def test_allow_entries_are_normalised():
    s = PolicySettings(usb_storage="block", usb_allow=[" 0781:5567 ", "0781:5567", "090c:1000:Ab12cd",
                                                       "090C:1000:AB12CD"])
    assert s.usb_allow == ["0781:5567", "090C:1000:Ab12cd"]


@pytest.mark.parametrize("bad", ["0781", "0781-5567", "781:5567", "0781:5567:with space", "zzzz:5567",
                                 "0781:5567:a:b"])
def test_malformed_entries_are_refused(bad):
    with pytest.raises(ValidationError):
        PolicySettings(usb_allow=[bad])


def test_unknown_mode_is_refused():
    with pytest.raises(ValidationError):
        PolicySettings(usb_storage="readonly")
