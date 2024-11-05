import pwd
import pytest

from pathlib import Path
from io import TextIOBase

from lcitool.containers import ContainerError, Docker, Podman


id_mapping = [
    ("--uidmap", "0:1:100"),
    ("--uidmap", "100:0:1"),
    ("--uidmap", "101:101:5900"),
    ("--gidmap", "0:1:100"),
    ("--gidmap", "100:0:1"),
    ("--gidmap", "101:101:5900"),
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
def mock_pwd(monkeypatch_module_scope):
    monkeypatch_module_scope.setattr(pwd, "getpwuid", get_pwuid)
    monkeypatch_module_scope.setattr(pwd, "getpwnam", get_pwuid)


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
    def patch_builtins_open(self, monkeypatch_class_scope):
        monkeypatch_class_scope.setattr("builtins.open",
                                        TestPodmanExtraArgs.mock_open)

    @pytest.mark.parametrize(
        "user, args",
        [
            pytest.param(0, [], id="root-numeric-id"),
            pytest.param("root", [], id="root-string-id"),
            pytest.param(1, id_mapping, id="testuser-numeric-id"),
            pytest.param("user", id_mapping, id="testuser-string-id")
        ]
    )
    def test_podman_extra_args(self, assert_equal, user, args, mock_pwd, podman):
        assert_equal(podman._extra_args(user), args)

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
    def patch_extra_args(self, monkeypatch_class_scope):
        monkeypatch_class_scope.setattr("lcitool.containers.Podman._extra_args",
                                        self.podman_extra_args)

    @pytest.mark.parametrize(
        "args, options",
        [
            pytest.param({"user": 0}, [], id="numeric-root"),
            pytest.param({"user": "root"}, [], id="string-root"),
            pytest.param({"user": 1}, [], id="numeric-testuser"),
            pytest.param({"user": "user"}, [], id="string-testuser"),
            pytest.param(
                dict(user=0, env=["FOO=bar", "BAR=baz"]),
                [
                    ("--env=FOO=bar",),
                    ("--env=BAR=baz",)
                ],
                id="environmental-variable-root"
            ),
            pytest.param(
                dict(user="user", env=["FOO=baz"]),
                [
                    ("--env=FOO=baz",),
                ],
                id="environmental-variable-testuser"
            ),
            pytest.param(
                dict(user="root", datadir="/abc"),
                [
                    ("--volume", "/abc:/root/datadir:z"),
                ],
                id="scratch-directory-root"
            ),
            pytest.param(
                dict(user=1, datadir="/tmp/src"),
                [
                    ("--volume", "/tmp/src:/home/user/datadir:z"),
                ],
                id="scratch-directory-testuser"
            ),
            pytest.param(
                dict(user=0, script="build"), [],
                id="script-file-root"
            ),
            pytest.param(
                dict(user=1, script="build"), [],
                id="script-file-testuser"
            ),
            pytest.param(
                dict(user=0, datadir="/abc", script="bundle.sh"),
                [
                    ("--volume", "/abc:/root/datadir:z"),
                ],
                id="scratch-directory-script-file-for-root"
            ),
            pytest.param(
                dict(user=1, datadir="/tmp/random", script="bundle"),
                [
                    ("--volume", "/tmp/random:/home/user/datadir:z"),
                ],
                id="scratch-directory-script-file-for-testuser"
            ),
            pytest.param(
                dict(user=0, env=["FOO=baz"], datadir="/abc", script="bundle.sh"),
                [
                    ("--volume", "/abc:/root/datadir:z"),
                    ("--env=FOO=baz",),
                ],
                id="env-scratch-directory-script-file-for-root"
            ),
            pytest.param(
                dict(user=1, env=["BAR=baz"], datadir="/tmp/random", script="bundle"),
                [
                    ("--volume", "/tmp/random:/home/user/datadir:z"),
                    ("--env=BAR=baz",),
                ],
                id="env-scratch-directory-script-file-for-testuser"
            )
        ]
    )
    def test_options(self, assert_equal, args, options, docker, podman,
                     mock_pwd, tmp_path):
        args["tempdir"] = tmp_path
        uid, gid, _, workdir = get_pwuid(args.get("user"))[2:6]
        template = [
            ("--user", f"{uid}:{gid}"),
            ("--workdir", f"{workdir}"),
            ("--ulimit", "nofile=1024:1024"),
            ("--cap-add", "SYS_PTRACE"),
        ]

        extra_option = []
        if args.get("script"):
            script_path = Path(tmp_path, args.get("script"))
            script_path.write_text("")  # to create the file
            args["script"] = script_path

            extra_option = [
                ("--volume", f"{Path(tmp_path, 'script')}:{workdir}/script:z")
            ]

        if args.get("user") == 1 or args.get("user") == "user":
            template.extend([
                ("--volume", f"{tmp_path}/passwd.copy:/etc/passwd:ro,z"),
                ("--volume", f"{tmp_path}/group.copy:/etc/group:ro,z"),
                ("--volume", f"{tmp_path}/home:{workdir}:z"),
            ])

        # test docker options
        actual = sorted(docker._build_args(**args))
        expected = sorted(template + extra_option + options)
        assert_equal(actual, expected)

        if args.get("user") == 1 or args.get("user") == "user":
            options += id_mapping

        # test podman options
        actual = sorted(podman._build_args(**args))
        expected = sorted(template + extra_option + options)
        assert_equal(actual, expected)


class TestContainerReference:

    def podman_images(self):
        return [
            {
                "Id": "8df5ae41ea341b6dd71961ff503a3357bd0b65091ccf282c2633ef175007a49c",
                "Names": ['localhost/foo:tag']
            },
            {
                "Id": "2720e26172a023c7245fd2d59f06452cb3743e3c5a26dd102c6a2294e473cdcd",
                "Names": ['docker.io/library/alpine:3.15']
            },
            {
                "Id": "a18e665d62d32d78eed320b32dce4bf49b3acf8f402cb936768fdd56cee04746",
                "Names": ['registry.gitlab.com/libvirt/libvirt/ci-fedora-36:latest']
            },
            {
                "Id": "6110febd7078d4555b6b80c3860554719056f36311f98821b20233b591027957",
                "Names": ['localhost/bar:latest', 'localhost/foo:latest']
            }
        ]

    def docker_images(self):
        return [
            {"ID": "a2517b2fbc71", "Repository": "foo", "Tag": "latest"},
            {"ID": "dd94cb611937", "Repository": "debian", "Tag": "11-slim"},
            {"ID": "75239e49e899", "Repository": "lcitool.fedora36", "Tag": "latest"}
        ]

    @pytest.fixture(scope="class", autouse=True)
    def patch_podman_images(self, monkeypatch_class_scope):
        monkeypatch_class_scope.setattr(Podman, "_images", self.podman_images)

    @pytest.fixture(scope="class", autouse=True)
    def patch_docker_images(self, monkeypatch_class_scope):
        monkeypatch_class_scope.setattr(Docker, "_images", self.docker_images)

    @pytest.mark.parametrize(
        "args",
        [
            pytest.param(["a2517b2", ""], id="image-id"),
            pytest.param(["debian", "11-slim"], id="name")
        ]
    )
    def test_docker_image_reference(self, args, docker):
        assert docker.image_exists(*args)

    @pytest.mark.parametrize(
        "args",
        [
            pytest.param(["", ""], id="empty-string"),
            pytest.param(["invalid", ""], id="invalid-name"),
            pytest.param(["lcitool.fedora36", ""], id="name"),
            pytest.param(["foo", "invalid"], id="name-invalid-tag")
        ]
    )
    def test_docker_image_reference_error(self, args, docker):
        assert docker.image_exists(*args) == False

    @pytest.mark.parametrize(
        "args",
        [
            pytest.param(["alpine", "3.15"], id="name"),
            pytest.param(["foo", "tag"], id="local-name-tag"),
            pytest.param(["localhost/foo", "latest"], id="alternative-image-name"),
            pytest.param(["localhost/bar", "latest"], id="local-registry-name-tag"),
            pytest.param(
                ["registry.gitlab.com/libvirt/libvirt/ci-fedora-36", "latest"],
                id="registry-name-tag"
            )
        ]
    )
    def test_podman_image_reference(self, args, podman):
        assert podman.image_exists(*args)

    @pytest.mark.parametrize(
        "args",
        [
            pytest.param(["", ""], id="empty-string"),
            pytest.param(["ci-fedora-36", ""], id="name"),
            pytest.param(["alpine", "latest"], id="name-invalid-tag")
        ]
    )
    def test_podman_image_reference_error(self, args, podman):
        assert podman.image_exists(*args) ==  False
