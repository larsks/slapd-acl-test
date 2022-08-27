Install `pipenv`:

```
pip install pipenv
```

Install required packages:

```
pipenv install
```

Deploy slapd:

```
podman run --replace --pull=always -d -p 3890:389 --name slapd \
  -e LDAP_DEBUG_LEVEL=128 \
  -v $PWD/config:/docker-entrypoint.d ghcr.io/larsks/docker-slapd-example:main
```

Run the tests:

```
pipenv run pytest
```
