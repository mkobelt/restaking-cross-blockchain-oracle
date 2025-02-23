// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import {PublicKey} from "../common/Account.sol";
import "../common/Events.sol";

contract StubRelay {
    modifier verify() {
        require(true, "verification failed");
        _;
    }

    function verifyRegistered(
        RegisteredEvent calldata /*ev*/,
        bytes calldata /*proof*/
    ) external pure verify() {}

    function verifyReplaced(
        ReplacedEvent calldata /*ev*/,
        bytes calldata /*proof*/
    ) external pure verify() {}

    function verifyExiting(
        ExitingEvent calldata /*ev*/,
        bytes calldata /*proof*/
    ) external pure verify() {}
}