# End-to-end Tests

## Testing the Demo file

This testing package does a bit of magic to invoke the docker-compose file found in `demo` as a pytest test. This acts as a simple end-to-end test. Other tests may be added in the future.

To see the execution of the docker-compose demo and its output, execute pytest with the `-s` flag:

```sh
uv run pytest -s -m e2e
```
