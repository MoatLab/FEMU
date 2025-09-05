import pytest
import sys

from pathlib import Path

from lcitool.packages import Packages
from lcitool.projects import Projects
from lcitool.targets import Targets
from lcitool.util import DataDir

from test_utils.mocks import libvirt, gi
import test_utils.utils as test_utils


def pytest_addoption(parser):
    parser.addoption(
        "--regenerate-output",
        help="regenerate output data set to reflect the changed inputs",
        default=False,
        action="store_true",
    )


def pytest_configure(config):
    opts = ["regenerate_output"]
    pytest.custom_args = {opt: config.getoption(opt) for opt in opts}


# These needs to be a global in order to compute ALL_PROJECTS and ALL_TARGETS
# at collection time.  Tests do not access it and use the fixtures below.
_PROJECTS = Projects(DataDir(Path(test_utils.base_data_dir())))
_TARGETS = Targets()

ALL_PROJECTS = sorted(_PROJECTS.names + list(_PROJECTS.internal.keys()))
ALL_TARGETS = sorted(_TARGETS.targets)

# We need to mock a few modules that we don't need for testing
sys.modules["libvirt"] = libvirt
sys.modules["gi"] = gi


def monkeypatch_context():
    with pytest.MonkeyPatch.context() as mp:
        yield mp


@pytest.fixture(scope="module")
def monkeypatch_module_scope():
    yield from monkeypatch_context()


@pytest.fixture(scope="class")
def monkeypatch_class_scope():
    yield from monkeypatch_context()


@pytest.fixture
def assert_equal(request, tmp_path_factory):
    def _assert_equal(actual, expected):
        tmp_dir = Path(tmp_path_factory.getbasetemp(), request.node.name)
        return test_utils._assert_equal(actual, expected, test_tmp_dir=tmp_dir)
    return _assert_equal


@pytest.fixture(scope="module")
def packages():
    return Packages()


@pytest.fixture(scope="module")
def projects():
    return _PROJECTS


@pytest.fixture(scope="module")
def targets():
    return _TARGETS
