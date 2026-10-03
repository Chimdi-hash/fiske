import copy
import importlib.util
import json
import sys
import types
from pathlib import Path

import pytest


ROOT = Path(__file__).resolve().parents[1]
CONTRACT = ROOT / "contracts" / "fiske.py"
BASE_TIME = "2026-01-01T00:00:00Z"
ALICE = "0x" + "1" * 40
BOB = "0x" + "2" * 40
CHARLIE = "0x" + "3" * 40
DAVE = "0x" + "4" * 40
ERIN = "0x" + "5" * 40


class ContractError(RuntimeError):
    pass


class ConsensusError(RuntimeError):
    pass


class Return:
    def __init__(self, calldata):
        self.calldata = calldata


class FakeTreeMap(dict):
    def __init__(self, vm):
        super().__init__()
        self.vm = vm

    def _read(self):
        if self.vm.in_nondet:
            self.vm.storage_reads_in_nondet += 1

    def get(self, key, default=None):
        self._read()
        return super().get(key, default)

    def __getitem__(self, key):
        self._read()
        return super().__getitem__(key)

    def __contains__(self, key):
        self._read()
        return super().__contains__(key)


class FakeLLM:
    def __init__(self):
        self.responses = []
        self.calls = []

    def set_responses(self, values):
        self.responses = [copy.deepcopy(value) for value in values]

    def exec_prompt(self, prompt, response_format=None):
        self.calls.append((prompt, response_format))
        if not self.responses:
            value = {"status": "CONTAINED"}
        elif len(self.responses) > 1:
            value = self.responses.pop(0)
        else:
            value = self.responses[0]
        if isinstance(value, BaseException):
            raise value
        return copy.deepcopy(value)


class FakeVM:
    Return = Return
    UserError = ContractError

    def __init__(self):
        self.in_nondet = False
        self.storage_reads_in_nondet = 0
        self.runs = 0
        self.validation_results = []

    def run_nondet(self, leader_fn, validator_fn):
        self.runs += 1
        self.in_nondet = True
        try:
            leader_value = leader_fn()
        finally:
            self.in_nondet = False
        self.in_nondet = True
        try:
            valid = validator_fn(Return(copy.deepcopy(leader_value)))
        finally:
            self.in_nondet = False
        self.validation_results.append(valid)
        if not valid:
            raise ConsensusError("proposal mismatch")
        return leader_value


def load_contract_module():
    fake_gl = types.SimpleNamespace()
    fake_gl.vm = types.SimpleNamespace(UserError=ContractError)
    fake_gl.Contract = object

    class Public:
        @staticmethod
        def view(fn):
            return fn

        class Write:
            def __call__(self, fn):
                return fn

        write = Write()

    fake_gl.public = Public()

    class StorageType:
        @classmethod
        def __class_getitem__(cls, value):
            return cls

    fake_gl.contract = types.SimpleNamespace(Contract=object)
    fake_gl.storage = types.SimpleNamespace(TreeMap=StorageType)

    fake_genlayer = types.ModuleType("genlayer")
    fake_genlayer.__all__ = ["gl", "TreeMap", "u256", "Address"]
    fake_genlayer.gl = fake_gl
    fake_genlayer.vm = fake_gl.vm
    fake_genlayer.public = fake_gl.public
    fake_genlayer.contract = fake_gl.contract
    fake_genlayer.storage = fake_gl.storage
    fake_genlayer.TreeMap = StorageType
    fake_genlayer.u256 = int
    fake_genlayer.Address = str
    fake_types = types.ModuleType("genlayer.types")
    fake_types.__all__ = ["TreeMap", "u256", "Address"]
    fake_types.TreeMap = StorageType
    fake_types.u256 = int
    fake_types.Address = str
    fake_genlayer.types = fake_types

    spec = importlib.util.spec_from_file_location("fiske_test_module", CONTRACT)
    module = importlib.util.module_from_spec(spec)
    previous = sys.modules.get("genlayer")
    previous_types = sys.modules.get("genlayer.types")
    sys.modules["genlayer"] = fake_genlayer
    sys.modules["genlayer.types"] = fake_types
    try:
        assert spec.loader is not None
        spec.loader.exec_module(module)
    finally:
        if previous is None:
            sys.modules.pop("genlayer", None)
        else:
            sys.modules["genlayer"] = previous
        if previous_types is None:
            sys.modules.pop("genlayer.types", None)
        else:
            sys.modules["genlayer.types"] = previous_types
    return module


class Harness:
    def __init__(self):
        self.module = load_contract_module()
        self.vm = FakeVM()
        self.llm = FakeLLM()
        self.gl = types.SimpleNamespace(
            vm=self.vm,
            nondet=types.SimpleNamespace(exec_prompt=self.llm.exec_prompt),
            message=types.SimpleNamespace(
                sender_address=ALICE, raw={"datetime": BASE_TIME},
            ),
        )
        self.module.gl = self.gl
        self.contract = self.module.Fiske()
        self.contract.anchor_records = FakeTreeMap(self.vm)
        self.contract.grant_records = FakeTreeMap(self.vm)
        self.contract.latest_anchor_by_owner = FakeTreeMap(self.vm)
        self.contract.latest_grant_by_holder = FakeTreeMap(self.vm)
        self.contract.anchor_count = 0
        self.contract.grant_count = 0

    def set_sender(self, sender):
        self.gl.message.sender_address = sender

    def set_time(self, timestamp):
        self.gl.message.raw["datetime"] = timestamp

    def set_status(self, status):
        self.llm.set_responses([{"status": status}, {"status": status}])

    def set_pair(self, leader_status, validator_status):
        self.llm.set_responses([
            {"status": leader_status}, {"status": validator_status},
        ])

    def set_raw(self, raw):
        self.llm.set_responses([raw, raw])

    def create_anchor(self, scope="May manage infrastructure expenses up to 25000 USDC and assign.",
                    can_branch=True, expires_at=0):
        self.set_sender(ALICE)
        return self.contract.establish_anchor(scope, can_branch, expires_at)

    def create_grant(self, upstream_id, holder=BOB,
                     scope="May pay 12000 USDC to a cloud infrastructure provider.",
                     can_branch=True, expires_at=0, status="CONTAINED",
                     sender=None):
        self.set_sender(ALICE if sender is None else sender)
        self.set_status(status)
        return self.contract.issue_grant(
            upstream_id, holder, scope, can_branch, expires_at,
        )


@pytest.fixture
def env():
    return Harness()


def expect_error(call, message=None):
    with pytest.raises((ContractError, ConsensusError)) as error:
        call()
    if message is not None:
        assert message in str(error.value)
    return error.value


def stored(contract, store_name, identifier):
    return json.loads(getattr(contract, store_name)[identifier])


def replace_stored(contract, store_name, identifier, value):
    getattr(contract, store_name)[identifier] = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
    )


def epoch(env):
    return env.module._get_timestamp()
