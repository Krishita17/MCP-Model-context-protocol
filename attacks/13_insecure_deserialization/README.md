# Insecure Deserialization

The server uses `pickle.loads()` on user-supplied base64 input. An attacker crafts a pickle payload that executes arbitrary code when deserialized.
