import pytest


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
