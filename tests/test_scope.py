from kubedelos.config import Settings
from kubedelos.scope import outside_scope


def test_same_scope_is_inside():
    configured = Settings(namespaces=["a", "b"], exclude_namespaces=["x"], selector="app=web")
    assert outside_scope(configured, configured.model_copy()) is None


def test_fewer_namespaces_is_inside():
    configured = Settings(namespaces=["a", "b"])
    assert outside_scope(configured, Settings(namespaces=["a"])) is None
    assert outside_scope(configured, Settings(namespaces=[])) is None


def test_namespace_outside_the_list():
    configured = Settings(namespaces=["a", "b"])
    assert (
        outside_scope(configured, Settings(namespaces=["a", "kube-system"]))
        == "namespace kube-system is outside the configured scope"
    )


def test_all_namespaces_cannot_reach_an_excluded_one():
    configured = Settings(exclude_namespaces=["kube-system"])
    requested = Settings(namespaces=["kube-system"])
    assert outside_scope(configured, requested) == "namespace kube-system is outside the configured scope"


def test_configured_exclusion_must_stay():
    configured = Settings(exclude_namespaces=["kube-system"])
    assert (
        outside_scope(configured, Settings(exclude_namespaces=[]))
        == "namespace kube-system is excluded by the configured scope"
    )


def test_extra_exclusions_are_inside():
    configured = Settings(exclude_namespaces=["kube-system"])
    assert outside_scope(configured, Settings(exclude_namespaces=["kube-system", "dev"])) is None


def test_image_exclusion_must_stay():
    configured = Settings(exclude_images=["registry.example.com/*"])
    assert (
        outside_scope(configured, Settings(exclude_images=[]))
        == "image exclusion registry.example.com/* is part of the configured scope"
    )
    assert outside_scope(configured, Settings(exclude_images=["registry.example.com/*", "other/*"])) is None


def test_selector_must_stay_when_configured():
    configured = Settings(namespace_selector="team=payments", selector="app=web")
    same = Settings(namespace_selector="team=payments", selector="app=web")
    assert outside_scope(configured, same) is None
    assert (
        outside_scope(configured, Settings(namespace_selector="team=other", selector="app=web"))
        == "namespace selector must stay team=payments"
    )
    assert outside_scope(configured, Settings(namespace_selector="team=payments")) == "label selector must stay app=web"


def test_any_selector_when_none_configured():
    requested = Settings(namespace_selector="team=x", selector="app=y")
    assert outside_scope(Settings(), requested) is None


def test_package_type_outside():
    configured = Settings(pkg_types=("os",))
    assert outside_scope(configured, Settings(pkg_types=("os", "library"))) == (
        "package type library is not in the configured scope"
    )


def test_os_only_from_os_and_library_is_inside():
    assert outside_scope(Settings(pkg_types=("os", "library")), Settings(pkg_types=("os",))) is None
