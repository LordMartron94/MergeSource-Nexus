# Nexus

Some of the implementation in this library is LLM-generated. Nexus is reused
as an extensive foundational core rather than a domain project or mastery goal.

Restored from the archived Nexus snapshot
`705f971421e9c2d31996f4446cd533ec73874a7a`, including the original source,
tests, ADRs, allocation-hijack header, and reference Helm configuration.
The active build uses CMake; `nexus.helm` is retained as archived material.

The public interface is `nexus.h`. The implementation covers platform and
primitive types, errors and assertions, memory, containers, strings, files,
processes, signals, threads, time, entropy, hashing, and identity.

From the MergeSource root:

```sh
make configure
make TARGET=nexus_tests JOBS=4
ctest --test-dir build/Debug --output-on-failure -R '^nexus_tests$'
```

Consumers link the CMake target `Nexus::Nexus`. Debug builds enable developer
assertions, memory guards, and allocation tracing consistently in the library
and its consumers; other configurations disable those development facilities.
