// SPDX-License-Identifier: MIT
pragma solidity ^0.8.13;

import "../common/MerkleTree.sol";
import "./AggregationVerifier.sol";
import "./SlashingVerifier.sol";
import "./StubRelay.sol";

import "../common/Events.sol";
import "../common/Account.sol";

contract ZKOracle is MerkleTree {
    using AccountHasher for Account;

    StubRelay immutable relay;
    AggregationVerifier immutable aggregationVerifier;
    SlashingVerifier immutable slashingVerifier;

    uint256 public constant AGGREGATOR_REWARD = 500000000000000;
    uint256 public constant VALIDATOR_REWARD = 20000000000;
    uint256 public constant MIN_BALANCE = VALIDATOR_REWARD;

    uint256 nextNonce = 0;

    mapping(uint256 => address) accounts;

    uint256 nextRequest;
    mapping(uint256 => uint256) requests;
    mapping(uint256 => bytes32) blocks;

    uint256 seedX;
    uint256 seedY;

    constructor(
        uint256 _levels,
        uint256 _seedX,
        uint256 _seedY,
        address aggregationVerifierAddress,
        address slashingVerifierAddress
    ) MerkleTree(_levels) {
        levels = _levels;
        seedX = _seedX;
        seedY = _seedY;
        aggregationVerifier = AggregationVerifier(aggregationVerifierAddress);
        slashingVerifier = SlashingVerifier(slashingVerifierAddress);
    }

    modifier nonceCheck(uint256 nonce) {
        require(nonce == nextNonce++, "nonce out-of-order");
        _;
    }

    modifier senderCheck(address expected) {
        require(expected == msg.sender, "invalid sender");
        _;
    }

    modifier minBalanceCheck() {
        require(msg.value == MIN_BALANCE, "need exactly MIN_BALANCE");
        _;
    }

    function register(
        RegisteredEvent memory ev,
        bytes calldata proof
    ) external payable nonceCheck(ev.nonce) senderCheck(ev.targetChainAddress) minBalanceCheck {
        relay.verifyRegistered(
            ev,
            proof
        );

        Account memory account = Account(
            ev.index,
            ev.pubKey,
            msg.value
        );
        accounts[account.index] = msg.sender;

        insert(account.hash());
    }

    function replace(
        ReplacedEvent memory ev,
        Account memory toReplace,
        uint256[] memory path,
        uint256[] memory helper,
        bytes calldata proof
    ) public payable nonceCheck(ev.nonce) senderCheck(ev.targetChainAddress) minBalanceCheck {
        require(ev.index == toReplace.index, "indices don't match");
        require(
            path[0] == toReplace.hash(),
            "leaf does not match account"
        );

        relay.verifyReplaced(
            ev,
            proof
        );

        Account memory replaced = Account(
            toReplace.index,
            ev.pubKey,
            msg.value
        );

        update(replaced.hash(), path, helper);
        payable(accounts[toReplace.index]).transfer(toReplace.balance);
        accounts[toReplace.index] = msg.sender;
    }

    function getBlockByNumber(uint256 number) public payable {
        require(msg.value >= getReward(), "value too low");

        requests[nextRequest] = number;

        nextRequest += 1;
    }

    function submitBlock(
        uint256 index,
        uint256 request,
        uint256 validators,
        bytes32 blockHash,
        uint256 postStateRoot,
        uint256 postSeedX,
        uint256 postSeedY,
        uint256[8] calldata zkProof
    ) public senderCheck(accounts[index]) {
        require(index == getAggregator(), "invalid aggregator");
        require(blocks[request] == 0, "already submitted");

        blocks[request] = blockHash;

        aggregationVerifier.verifyProof(zkProof, [
            getRoot(),
            postStateRoot,
            uint256(blockHash),
            request,
            validators,
            index,
            seedX,
            seedY,
            postSeedX,
            postSeedY
        ]);

        seedX = postSeedX;
        seedY = postSeedY;

        setRoot(postStateRoot);
    }

    function slash(
        uint256 slasherIndex,
        uint256 slashedIndex,
        uint256 request,
        uint256 postStateRoot,
        uint256[8] calldata zkProof
    ) public {
        require(blocks[request] != 0, "pending request");

        slashingVerifier.verifyProof(zkProof, [
            getRoot(),
            postStateRoot,
            uint256(blocks[request]),
            request,
            slasherIndex,
            slashedIndex
        ]);

        setRoot(postStateRoot);
    }

    function getAggregator() public view returns (uint) {
        return seedX % 2 ** getLevels();
    }

    function exit(
        uint256 beneficiaryIndex,
        Account memory exitor,
        uint256[] memory path,
        uint256[] memory helper,
        ExitingEvent calldata ev,
        bytes memory proof
    ) public nonceCheck(ev.nonce) senderCheck(accounts[beneficiaryIndex]) {
        require(path[0] == exitor.hash(), "leaf does not match exitor");

        relay.verifyExiting(ev, proof);

        Account memory empty = Account(exitor.index, PublicKey(0, 0), 0);
        update(empty.hash(), path, helper);

        if (beneficiaryIndex == exitor.index) {
            payable(msg.sender).transfer(exitor.balance);
        } else {
            payable(msg.sender).transfer(MIN_BALANCE);
            payable(accounts[exitor.index]).transfer(exitor.balance - MIN_BALANCE);
        }

        delete accounts[exitor.index];
    }

    function getSeed() public view returns (uint256, uint256) {
        return (seedX, seedY);
    }

    function getReward() public view returns (uint256) {
        return
            AGGREGATOR_REWARD + (getNextLeafIndex() / 2 + 1) * VALIDATOR_REWARD;
    }
}
