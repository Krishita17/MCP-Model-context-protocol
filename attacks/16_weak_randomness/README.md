# Weak Randomness

The server generates security tokens using `random.randint()` seeded with `time.time()`. An attacker who knows the approximate creation time can predict every token.
