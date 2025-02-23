// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "./MiMC.sol";

struct PublicKey {
    uint256 x;
    uint256 y;
}

struct Account {
    uint256 index;
    PublicKey pubKey;
    uint256 balance;
}

library AccountHasher {
    function hash(Account memory account) internal pure returns (uint256) {
        uint[] memory input = new uint[](4);
        input[0] = account.index;
        input[1] = account.pubKey.x;
        input[2] = account.pubKey.y;
        input[3] = account.balance;
        return MiMC.hash(input);
    }
}
