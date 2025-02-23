// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "../common/MerkleTree.sol";
import {Account, PublicKey, AccountHasher} from "../common/Account.sol";
import "../common/Events.sol";
import "./SlashingVerifier.sol";

contract Restaking is MerkleTree {
    using AccountHasher for Account;

    uint256 public constant EXIT_DELAY = 30 * 60;

    SlashingVerifier immutable slashingVerifier;

    // Replay prevention
    mapping(uint256 => mapping(uint256 => bool)) disputedRequests;
    uint256 nonce = 0;

    mapping(address => uint256) exitTimes;
    mapping(uint256 => address) accounts;

    event Registered(RegisteredEvent);
    event Replaced(ReplacedEvent);
    event Exiting(ExitingEvent);

    constructor(
        uint256 _levels,
        SlashingVerifier verifier
    ) MerkleTree(_levels) {
        slashingVerifier = verifier;
    }

    modifier senderCheck(address expected) {
        require(expected == msg.sender, "invalid sender");
        _;
    }

    function register(
        PublicKey calldata publicKey,
        address targetChainAddress
    ) external payable {
        Account memory account = Account(
            getNextLeafIndex(),
            publicKey,
            msg.value
        );

        accounts[account.index] = msg.sender;

        insert(account.hash());

        emit Registered(RegisteredEvent(
            account.index,
            targetChainAddress,
            account.pubKey,
            nonce++
        ));
    }

    function replace(
        PublicKey memory publicKey,
        address targetChainAddress,
        Account memory toReplace,
        uint256[] memory path,
        uint256[] memory helper
    ) public payable {
        require(msg.value >= toReplace.balance, "value too low");
        require(
            path[0] == toReplace.hash(),
            "leaf does not match account"
        );

        Account memory replaced = Account(
            toReplace.index,
            publicKey,
            msg.value
        );

        update(replaced.hash(), path, helper);
        payable(accounts[toReplace.index]).transfer(toReplace.balance);

        emit Replaced(ReplacedEvent(
            toReplace.index,
            targetChainAddress,
            publicKey,
            nonce++
        ));

        accounts[toReplace.index] = msg.sender;
    }

    function slash(
        uint256 slashedIndex,
        uint256 request,
        bytes32 blockHash,
        uint256 postStateRoot,
        uint256[8] calldata zkProof
    ) external {
        require(!disputedRequests[request][slashedIndex], "already disputed");

        disputedRequests[request][slashedIndex] = true;

        slashingVerifier.verifyProof(zkProof, [
            getRoot(),
            postStateRoot,
            request,
            uint256(blockHash),
            slashedIndex
        ]);

        setRoot(postStateRoot);

        // TODO Transfer the slashed stake to the aggregator
    }

    function exit(uint256 exitorIndex) external senderCheck(accounts[exitorIndex]) {
        exitTimes[msg.sender] = block.timestamp + EXIT_DELAY;

        emit Exiting(ExitingEvent(
            exitorIndex,
            nonce++
        ));
    }

    function withdraw(
        Account memory exitor,
        uint256[] memory path,
        uint256[] memory helper
    ) external senderCheck(accounts[exitor.index]) {
        require(block.timestamp < exitTimes[msg.sender], "time not passed");
        require(path[0] == exitor.hash(), "leaf does not match account");

        payable(msg.sender).transfer(exitor.balance);
        delete accounts[exitor.index];

        Account memory empty = Account(exitor.index, PublicKey(0, 0), 0);
        update(empty.hash(), path, helper);
    }
}
