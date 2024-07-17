// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

import "./Verifier.sol";

contract CarbonCreditsContract {

    Halo2Verifier public halo2Verifier;

    //mapping(address => bool) public proofStatus;
    mapping(address => uint256) public balances;

    event ProofSubmitted(address indexed submitter, uint256[] instances, bytes proof);

    constructor(address _halo2Verifier) {
        halo2Verifier = Halo2Verifier(_halo2Verifier);
    }

    function claimCredits(bytes calldata proof, uint256[] calldata instances) public {
        //bytes32 instancesHash = keccak256(abi.encodePacked(instances));
        //require(instancesHash == inputHash, "Input hash does not match");
        require(halo2Verifier.verifyProof(proof, instances), "Proof verification failed");
        // Logic to mint carbon credits for the sender based on the provided image hash
        uint256 amount = 100;
        balances[msg.sender] += amount;
        emit ProofSubmitted(msg.sender, instances, proof);
    }
}
