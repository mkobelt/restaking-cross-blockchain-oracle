// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {PublicKey} from "./Account.sol";

struct RegisteredEvent {
    uint256 index;
    address targetChainAddress;
    PublicKey pubKey;
    uint256 nonce;
}

struct ReplacedEvent {
    uint256 index;
    address targetChainAddress;
    PublicKey pubKey;
    uint256 nonce;
}

struct ExitingEvent {
    uint256 index;
    uint256 nonce;
}
