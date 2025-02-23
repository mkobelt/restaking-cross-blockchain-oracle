# Securing Cross-Blockchain Oracles with Restaking

This repository hosts a prototype for a proof-of-stake cross-blockchain oracle.
It extends another research prototype, [zkOracle](https://github.com/soberm/zkOracle), by adding support for restaking.
For more details, refer to the report under `report/`.

Compilation of the smart contracts is done through `forge build` and zero-knowledge proof system generation through `go run cmd/main.go` (working directory set to `circuits/`).
