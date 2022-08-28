# pylint: disable=no-member,redefined-outer-name,missing-module-docstring,wrong-import-order

import ldap
import pytest
import random
import string

from nearly import Nearly


@pytest.fixture
def randstring():
    return "".join(random.choices(string.ascii_letters, k=10)).encode()


@pytest.fixture
def anon_slapd():
    slapd = ldap.initialize("ldap://localhost:3890")
    slapd.simple_bind("", "")
    return slapd


@pytest.fixture
def sssd_slapd():
    slapd = ldap.initialize("ldap://localhost:3890")
    slapd.simple_bind("uid=sssd,ou=system,dc=r1,dc=internal", "secret")
    return slapd


@pytest.fixture
def user1_slapd():
    slapd = ldap.initialize("ldap://localhost:3890")
    slapd.simple_bind("cn=user1,ou=users,dc=r1,dc=internal", "secret1")
    return slapd


@pytest.fixture
def user2_slapd():
    slapd = ldap.initialize("ldap://localhost:3890")
    slapd.simple_bind("cn=user2,ou=users,dc=r1,dc=internal", "secret2")
    return slapd


def test_anon_list_users(anon_slapd):
    """anonymous should be able to list ou=users"""

    have = dict(
        anon_slapd.search_s(
            "ou=users,dc=r1,dc=internal", ldap.SCOPE_SUBTREE, "objectclass=*"
        )
    )

    assert Nearly(have) == {
        "cn=user1,ou=users,dc=r1,dc=internal": {"sn": ..., "cn": ...},
        "cn=user2,ou=users,dc=r1,dc=internal": {"sn": ..., "cn": ...},
        "ou=nested,ou=users,dc=r1,dc=internal": ...,
    }


def test_anon_list_groups(anon_slapd):
    """anonymous should be able to list ou=groups"""

    have = dict(
        anon_slapd.search_s(
            "ou=groups,dc=r1,dc=internal", ldap.SCOPE_SUBTREE, "objectclass=*"
        )
    )

    assert Nearly(have) == {
        "cn=root,ou=groups,dc=r1,dc=internal": ...,
        "ou=nested,ou=groups,dc=r1,dc=internal": ...,
    }


def test_sssd_list_users(sssd_slapd):
    """sssd should be able to list users including userPassword attribute"""

    have = dict(
        sssd_slapd.search_s(
            "ou=users,dc=r1,dc=internal", ldap.SCOPE_SUBTREE, "objectclass=*"
        )
    )

    assert Nearly(have) == {
        "ou=users,dc=r1,dc=internal": ...,
        "ou=nested,ou=users,dc=r1,dc=internal": ...,
        "cn=user1,ou=users,dc=r1,dc=internal": {
            "objectClass": ...,
            "sn": ...,
            "cn": ...,
            "userPassword": ...,
        },
        "cn=user2,ou=users,dc=r1,dc=internal": {
            "objectClass": ...,
            "sn": ...,
            "cn": ...,
            "userPassword": ...,
        },
    }


def test_sssd_list_groups(sssd_slapd):
    """sssd should be able to list groups"""

    have = dict(
        sssd_slapd.search_s(
            "ou=groups,dc=r1,dc=internal", ldap.SCOPE_SUBTREE, "objectclass=*"
        )
    )

    assert Nearly(have) == {
        "ou=groups,dc=r1,dc=internal": ...,
        "cn=root,ou=groups,dc=r1,dc=internal": ...,
        "ou=nested,ou=groups,dc=r1,dc=internal": ...,
    }


def test_user1_list_users(user1_slapd):
    """user1 should be able to list ou=users and contained ous"""

    have = dict(
        user1_slapd.search_s(
            "ou=users,dc=r1,dc=internal", ldap.SCOPE_SUBTREE, "objectclass=*"
        )
    )

    assert Nearly(have) == {
        "ou=users,dc=r1,dc=internal": ...,
        "cn=user1,ou=users,dc=r1,dc=internal": {
            "userPassword": ...,
            ...: None,
        },
        "cn=user2,ou=users,dc=r1,dc=internal": {
            "userPassword": ...,
            ...: None,
        },
        "ou=nested,ou=users,dc=r1,dc=internal": ...,
        "cn=testuser,ou=nested,ou=users,dc=r1,dc=internal": ...,
    }


def test_user1_list_groups(user1_slapd):
    """user1 should be able to list ou=groups and contained ous"""

    have = dict(
        user1_slapd.search_s(
            "ou=groups,dc=r1,dc=internal", ldap.SCOPE_SUBTREE, "objectclass=*"
        )
    )

    assert Nearly(have) == {
        "ou=groups,dc=r1,dc=internal": ...,
        "cn=root,ou=groups,dc=r1,dc=internal": ...,
        "ou=nested,ou=groups,dc=r1,dc=internal": ...,
        "cn=testgroup,ou=nested,ou=groups,dc=r1,dc=internal": ...,
    }


def test_user1_modify_user2(user1_slapd, randstring):
    """user1 should be able to modify other users

    user1 is a member of cn=root,ou=groups,dc=r1,dc=internal, which
    is granted write access to the entire dc=r1,dc=internal subtree.
    """

    orig = user1_slapd.search_s(
        "cn=user2,ou=users,dc=r1,dc=internal",
        ldap.SCOPE_BASE,
    )

    try:
        user1_slapd.modify_s(
            "cn=user2,ou=users,dc=r1,dc=internal",
            [(ldap.MOD_REPLACE, "sn", randstring)],
        )

        have = user1_slapd.search_s(
            "cn=user2,ou=users,dc=r1,dc=internal",
            ldap.SCOPE_BASE,
        )

        assert have[0][1]["sn"] == [randstring]
    finally:
        user1_slapd.modify_s(
            "cn=user2,ou=users,dc=r1,dc=internal",
            [(ldap.MOD_REPLACE, "sn", orig[0][1]["sn"])],
        )


def test_user2_modify_user1(user2_slapd, randstring):
    """user2 should not be able to modify user1

    user2 has no privilged access and should not have write access to any
    other entries
    """

    with pytest.raises(ldap.INSUFFICIENT_ACCESS):
        user2_slapd.modify_s(
            "cn=user1,ou=users,dc=r1,dc=internal",
            [(ldap.MOD_REPLACE, "sn", randstring)],
        )


def test_user2_modify_self(user2_slapd, randstring):
    """user2 should be able to modify self

    an authenticated user should be able to modify their own entry
    """

    orig = user2_slapd.search_s(
        "cn=user2,ou=users,dc=r1,dc=internal",
        ldap.SCOPE_BASE,
    )

    try:
        user2_slapd.modify_s(
            "cn=user2,ou=users,dc=r1,dc=internal",
            [(ldap.MOD_REPLACE, "sn", randstring)],
        )

        have = user2_slapd.search_s(
            "cn=user2,ou=users,dc=r1,dc=internal",
            ldap.SCOPE_BASE,
        )

        assert have[0][1]["sn"] == [randstring]
    finally:
        user2_slapd.modify_s(
            "cn=user2,ou=users,dc=r1,dc=internal",
            [(ldap.MOD_REPLACE, "sn", orig[0][1]["sn"])],
        )
