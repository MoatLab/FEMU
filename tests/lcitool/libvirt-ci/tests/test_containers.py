import pwd
import pytest

from pathlib import Path
from io import TextIOBase
from _pytest.monkeypatch import MonkeyPatch
from test_utils.utils import assert_equal_list

from lcitool.containers import ContainerError, Docker, Podman


id_mapping = [
    "--uidmap", "0:1:100",
    "--uidmap", "100:0:1",
    "--uidmap", "101:101:5900",
    "--gidmap", "0:1:100",
    "--gidmap", "100:0:1",
    "--gidmap", "101:101:5900"
]


def get_pwuid(id):
    """Mock funtion for pwd.getpwuid"""

    root_user = ["root", "x", 0, 0, "Mr root", "/root", "/bin/sh"]
    test_user = ["user", "x", 100, 100, "Mr user", "/home/user", "/bin/sh"]
    db = {"root": root_user, 0: root_user, 1: test_user, "user": test_user}
    return db[id]


class MockSubUidGidTextIO(TextIOBase):
    """Mock class for builtins.open"""

    def __init__(self, file, **kwargs):
        pass

    def read(self, *kwargs):
        # we only care about the last column for id mapping
        # (this is the only item we need in Podman._extra_args)
        return "_:_:6000"


@pytest.fixture(scope="module")
def mock_pwd():
    monkeypatch = MonkeyPatch()
    monkeypatch.setattr(pwd, "getpwuid", get_pwuid)
    monkeypatch.setattr(pwd, "getpwnam", get_pwuid)
    yield monkeypatch
    monkeypatch.undo()


@pytest.fixture(scope="module")
def podman():
    return Podman()


@pytest.fixture(scope="module")
def docker():
    return Docker()


class TestPodmanExtraArgs:
    """Unit test for Podman()._extra_args"""

    @staticmethod
    def mock_open(file, **kwargs):
        return MockSubUidGidTextIO(file, **kwargs)

    @pytest.fixture(scope="class", autouse=True)
    def patch_builtins_open(self):
        monkeypatch = MonkeyPatch()
        monkeypatch.setattr("builtins.open", TestPodmanExtraArgs.mock_open)
        yield monkeypatch
        monkeypatch.undo()

    @pytest.mark.parametrize(
        "user, args",
        [
            pytest.param(0, [], id="root-numeric-id"),
            pytest.param("root", [], id="root-string-id"),
            pytest.param(1, id_mapping, id="testuser-numeric-id"),
            pytest.param("user", id_mapping, id="testuser-string-id")
        ]
    )
    def test_podman_extra_args(self, user, args, mock_pwd, podman):
        assert_equal_list(podman._extra_args(user), args, [], "item")

    @pytest.mark.parametrize(
        "user, exception",
        [
            pytest.param(None, TypeError, id="NoneType-user"),
            pytest.param([], TypeError, id="non-string-and-numeric-user"),
            pytest.param("nonexistent", ContainerError, id="nonexistent-user"),
        ]
    )
    def test_extra_args_invalid_input(self, user, exception, mock_pwd, podman):
        with pytest.raises(exception):
            podman._extra_args(user)


class TestEngineOptions:
    """Unit test class for Container._build_args function"""

    def podman_extra_args(self, user):
        _, _, uid, _, _, _, _ = get_pwuid(user)
        if uid == 0:
            return []
        return id_mapping

    @pytest.fixture(scope="class", autouse=True)
    def patch_extra_args(self):
        monkeypatch = MonkeyPatch()
        monkeypatch.setattr("lcitool.containers.Podman._extra_args", self.podman_extra_args)
        yield monkeypatch
        monkeypatch.undo()

    @pytest.mark.parametrize(
        "args, options",
        [
            pytest.param({"user": 0}, [], id="numeric-root"),
            pytest.param({"user": "root"}, [], id="string-root"),
            pytest.param({"user": 1}, [], id="numeric-testuser"),
            pytest.param({"user": "user"}, [], id="string-testuser"),
            pytest.param(
                dict(user=0, env=["FOO=bar", "BAR=baz"]),
                ["--env=FOO=bar", "--env=BAR=baz"],
                id="environmental-variable-root"
            ),
            pytest.param(
                dict(user="user", env=["FOO=baz"]),
                ["--env=FOO=baz"],
                id="environmental-variable-testuser"
            ),
            pytest.param(
                dict(user="root", datadir="/abc"),
                ["--volume", "/abc:/root/datadir:z", "--workdir", "/root"],
                id="scratch-directory-root"
            ),
            pytest.param(
                dict(user=1, datadir="/tmp/src"),
                [
                    "--volume", "/tmp/src:/home/user/datadir:z",
                    "--workdir", "/home/user"
                ],
                id="scratch-directory-testuser"
            ),
            pytest.param(
                dict(user=0, script="build"),
                ["--workdir", "/root"],
                id="script-file-root"
            ),
            pytest.param(
                dict(user=1, script="build"),
                ["--workdir", "/home/user"],
                id="script-file-testuser"
            ),
            pytest.param(
                dict(user=0, datadir="/abc", script="bundle.sh"),
                [
                    "--volume", "/abc:/root/datadir:z",
                    "--workdir", "/root"
                ],
                id="scratch-directory-script-file-for-root"
            ),
            pytest.param(
                dict(user=1, datadir="/tmp/random", script="bundle"),
                [
                    "--volume", "/tmp/random:/home/user/datadir:z",
                    "--workdir", "/home/user"
                ],
                id="scratch-directory-script-file-for-testuser"
            ),
            pytest.param(
                dict(user=0, env=["FOO=baz"], datadir="/abc", script="bundle.sh"),
                [
                    "--volume", "/abc:/root/datadir:z",
                    "--env=FOO=baz",
                    "--workdir", "/root"
                ],
                id="env-scratch-directory-script-file-for-root"
            ),
            pytest.param(
                dict(user=1, env=["BAR=baz"], datadir="/tmp/random", script="bundle"),
                [
                    "--volume", "/tmp/random:/home/user/datadir:z",
                    "--env=BAR=baz",
                    "--workdir", "/home/user"
                ],
                id="env-scratch-directory-script-file-for-testuser"
            )
        ]
    )
    def test_options(self, args, options, docker, podman, mock_pwd, tmp_path):
        args["tempdir"] = tmp_path
        uid, gid, _, workdir = get_pwuid(args.get("user"))[2:6]
        template = [
            "--user", f"{uid}:{gid}",
            "--volume", f"{tmp_path}/passwd.copy:/etc/passwd:ro,z",
            "--volume", f"{tmp_path}/group.copy:/etc/group:ro,z",
            "--ulimit", "nofile=1024:1024",
            "--cap-add", "SYS_PTRACE"
        ]

        extra_option = []
        if args.get("script"):
            script_path = Path(tmp_path, args.get("script"))
            script_path.write_text("")  # to create the file
            args["script"] = script_path

            extra_option = [
                "--volume", f"{Path(tmp_path, 'script')}:{workdir}/script:z"
            ]

        # test docker options
        assert_equal_list(
            docker._build_args(**args),
            template + extra_option + options,
            [], "item"
        )

        if args.get("user") == 1 or args.get("user") == "user":
            options += id_mapping

        # test podman options
        assert_equal_list(
            podman._build_args(**args),
            template + extra_option + options,
            [], "item"
        )
