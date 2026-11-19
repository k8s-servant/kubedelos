"""The network_policy builder must be able to express an absent policyTypes, which Kubernetes defaults itself."""

from tests.kube import fakes


def test_network_policy_leaves_policy_types_unset_by_default():
    spec = fakes.network_policy("p", "web").spec
    assert spec.policy_types is None and spec.egress is None


def test_network_policy_passes_policy_types_through_verbatim():
    assert fakes.network_policy("p", "web", policy_types=[]).spec.policy_types == []
    assert fakes.network_policy("p", "web", policy_types=["Egress"]).spec.policy_types == ["Egress"]


def test_network_policy_egress_adds_a_rule_without_touching_policy_types():
    spec = fakes.network_policy("p", "web", egress=True).spec
    assert spec.policy_types is None and len(spec.egress) == 1
