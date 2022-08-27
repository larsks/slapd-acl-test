# pylint: disable=no-member,redefined-outer-name,missing-module-docstring

import random
import string

import pytest

import ldap


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
    have = dict(
        anon_slapd.search_s(
            "ou=users,dc=r1,dc=internal", ldap.SCOPE_SUBTREE, "objectclass=*"
        )
    )

    # anonymous should not see ou=users (only search access)
    assert "ou=users,dc=r1,dc=internal" not in have

    # anonymous should be able to see entries in ou=users
    assert "cn=user1,ou=users,dc=r1,dc=internal" in have

    # anonymous should not be able to see entries in ou=nested,ou=nsers
    assert "cn=testuser,ou=nested,ou=users,dc=r1,dc=internal" not in have

    # anonymous should not be able to see userPassword attribute
    assert not any("userPassword" in x for x in have.values())


def test_anon_list_groups(anon_slapd):
    have = dict(
        anon_slapd.search_s(
            "ou=groups,dc=r1,dc=internal", ldap.SCOPE_SUBTREE, "objectclass=*"
        )
    )

    # anonymous should not see ou=groups (only search access)
    assert "ou=groups,dc=r1,dc=internal" not in have

    # anonymous should see entries in ou=groups
    assert "cn=root,ou=groups,dc=r1,dc=internal" in have

    # anonymous should not see entries in ou=nested,ou=groups
    assert "cn=testgroup,ou=nested,ou=groups,dc=r1,dc=internal" not in have


def test_sssd_list_users(sssd_slapd):
    have = dict(
        sssd_slapd.search_s(
            "ou=users,dc=r1,dc=internal", ldap.SCOPE_SUBTREE, "objectclass=*"
        )
    )

    # sssd should be able to see ou=users entry
    assert "ou=users,dc=r1,dc=internal" in have

    # sssd should be able to see entries in ou=users
    assert "cn=user1,ou=users,dc=r1,dc=internal" in have

    # sssd should not be able to see entries in ou=nested,ou=users
    assert "cn=testuser,ou=nested,ou=users,dc=r1,dc=internal" not in have

    # sssd should be able to usee userpassword attribute
    assert any("userPassword" in x for x in have.values())


def test_sssd_list_groups(sssd_slapd):
    have = dict(
        sssd_slapd.search_s(
            "ou=groups,dc=r1,dc=internal", ldap.SCOPE_SUBTREE, "objectclass=*"
        )
    )

    # sssd should be able to see ou=groups entry
    assert "ou=groups,dc=r1,dc=internal" in have

    # sssd should be able to see entries in ou=groups
    assert "cn=root,ou=groups,dc=r1,dc=internal" in have

    # sssd should not be able to see entries in ou=groups
    assert "cn=testgroup,ou=nested,ou=groups,dc=r1,dc=internal" not in have


def test_user1_list_users(user1_slapd):
    have = dict(
        user1_slapd.search_s(
            "ou=users,dc=r1,dc=internal", ldap.SCOPE_SUBTREE, "objectclass=*"
        )
    )

    # user1 should be able to see ou=users entry
    assert "ou=users,dc=r1,dc=internal" in have

    # user1 should be able to see entries in ou=users
    assert "cn=user1,ou=users,dc=r1,dc=internal" in have

    # user1 should be able to see entries in ou=nested,ou=users
    assert "cn=testuser,ou=nested,ou=users,dc=r1,dc=internal" in have

    # user1 should be able to usee userpassword attribute
    assert any("userPassword" in x for x in have.values())


def test_user1_list_groups(user1_slapd):
    have = dict(
        user1_slapd.search_s(
            "ou=groups,dc=r1,dc=internal", ldap.SCOPE_SUBTREE, "objectclass=*"
        )
    )

    # user1 should be able to see ou=groups entry
    assert "ou=groups,dc=r1,dc=internal" in have

    # user1 should be able to see entries in ou=groups
    assert "cn=root,ou=groups,dc=r1,dc=internal" in have

    # user1 should be able to see entries in ou=nested,ou=groups
    assert "cn=testgroup,ou=nested,ou=groups,dc=r1,dc=internal" in have


def test_user1_modify_user2(user1_slapd, randstring):
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
    with pytest.raises(ldap.INSUFFICIENT_ACCESS):
        user2_slapd.modify_s(
            "cn=user1,ou=users,dc=r1,dc=internal",
            [(ldap.MOD_REPLACE, "sn", randstring)],
        )


def test_user2_modify_self(user2_slapd, randstring):
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
