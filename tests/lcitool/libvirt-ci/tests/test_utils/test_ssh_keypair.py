# test_ssh_keypair: test that a correct SSH keypair abstract layer is created
#
# Copyright (C) 2023 Red Hat, Inc.
#
# SPDX-License-Identifier: GPL-2.0-or-later

import pytest

from lcitool.util import SSHKeyPair, SSHPublicKey, SSHPrivateKey
import test_utils.utils as test_utils

from pathlib import Path


@pytest.mark.parametrize(
    "keyname",
    [
        pytest.param("id_ed25519.pub", id="derive_path_from_pubkey"),
        pytest.param("id_ed25519", id="derive_path_from_privkey"),
    ]
)
def test_keypair_load(keyname):
    key_path = Path(test_utils.test_data_indir(__file__, "utils"), keyname)
    SSHKeyPair(key_path)


@pytest.mark.parametrize(
    "keyname",
    [
        pytest.param("id_ed25519_noprivkey.pub", id="missing_key_counterpart"),
        pytest.param("foo.pub", id="non_existent_key"),
    ]
)
def test_keypair_load_error(keyname):
    key_path = Path(test_utils.test_data_indir(__file__, "utils"), keyname)
    with pytest.raises(FileNotFoundError):
        SSHKeyPair(key_path)


@pytest.mark.parametrize(
    "key_path, cls",
    [
        pytest.param(Path(test_utils.test_data_indir(__file__, "utils"),
                          "id_ed25519.pub"), SSHPublicKey,
                     id="public_key"),
        pytest.param(Path(test_utils.test_data_indir(__file__, "utils"),
                          "id_ed25519"), SSHPrivateKey,
                     id="private_key"),
    ]
)
def test_read_key(assert_equal, key_path, cls):
    if cls is SSHPublicKey:
        assert_equal(str(SSHPublicKey(key_path)) + "\n", key_path)
    else:
        # private key must only be read by SSH primitives
        assert_equal(str(SSHPrivateKey(key_path)), "")
