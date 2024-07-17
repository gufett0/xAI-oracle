// SPDX-License-Identifier: MIT

pragma solidity ^0.8.0;

contract Halo2Verifier {
    uint256 internal constant    PROOF_LEN_CPTR = 0x6014f51944;
    uint256 internal constant        PROOF_CPTR = 0x64;
    uint256 internal constant NUM_INSTANCE_CPTR = 0x0c44;
    uint256 internal constant     INSTANCE_CPTR = 0x0c64;

    uint256 internal constant FIRST_QUOTIENT_X_CPTR = 0x04e4;
    uint256 internal constant  LAST_QUOTIENT_X_CPTR = 0x05a4;

    uint256 internal constant                VK_MPTR = 0x0480;
    uint256 internal constant         VK_DIGEST_MPTR = 0x0480;
    uint256 internal constant     NUM_INSTANCES_MPTR = 0x04a0;
    uint256 internal constant                 K_MPTR = 0x04c0;
    uint256 internal constant             N_INV_MPTR = 0x04e0;
    uint256 internal constant             OMEGA_MPTR = 0x0500;
    uint256 internal constant         OMEGA_INV_MPTR = 0x0520;
    uint256 internal constant    OMEGA_INV_TO_L_MPTR = 0x0540;
    uint256 internal constant   HAS_ACCUMULATOR_MPTR = 0x0560;
    uint256 internal constant        ACC_OFFSET_MPTR = 0x0580;
    uint256 internal constant     NUM_ACC_LIMBS_MPTR = 0x05a0;
    uint256 internal constant NUM_ACC_LIMB_BITS_MPTR = 0x05c0;
    uint256 internal constant              G1_X_MPTR = 0x05e0;
    uint256 internal constant              G1_Y_MPTR = 0x0600;
    uint256 internal constant            G2_X_1_MPTR = 0x0620;
    uint256 internal constant            G2_X_2_MPTR = 0x0640;
    uint256 internal constant            G2_Y_1_MPTR = 0x0660;
    uint256 internal constant            G2_Y_2_MPTR = 0x0680;
    uint256 internal constant      NEG_S_G2_X_1_MPTR = 0x06a0;
    uint256 internal constant      NEG_S_G2_X_2_MPTR = 0x06c0;
    uint256 internal constant      NEG_S_G2_Y_1_MPTR = 0x06e0;
    uint256 internal constant      NEG_S_G2_Y_2_MPTR = 0x0700;

    uint256 internal constant CHALLENGE_MPTR = 0x0c20;

    uint256 internal constant THETA_MPTR = 0x0c20;
    uint256 internal constant  BETA_MPTR = 0x0c40;
    uint256 internal constant GAMMA_MPTR = 0x0c60;
    uint256 internal constant     Y_MPTR = 0x0c80;
    uint256 internal constant     X_MPTR = 0x0ca0;
    uint256 internal constant  ZETA_MPTR = 0x0cc0;
    uint256 internal constant    NU_MPTR = 0x0ce0;
    uint256 internal constant    MU_MPTR = 0x0d00;

    uint256 internal constant       ACC_LHS_X_MPTR = 0x0d20;
    uint256 internal constant       ACC_LHS_Y_MPTR = 0x0d40;
    uint256 internal constant       ACC_RHS_X_MPTR = 0x0d60;
    uint256 internal constant       ACC_RHS_Y_MPTR = 0x0d80;
    uint256 internal constant             X_N_MPTR = 0x0da0;
    uint256 internal constant X_N_MINUS_1_INV_MPTR = 0x0dc0;
    uint256 internal constant          L_LAST_MPTR = 0x0de0;
    uint256 internal constant         L_BLIND_MPTR = 0x0e00;
    uint256 internal constant             L_0_MPTR = 0x0e20;
    uint256 internal constant   INSTANCE_EVAL_MPTR = 0x0e40;
    uint256 internal constant   QUOTIENT_EVAL_MPTR = 0x0e60;
    uint256 internal constant      QUOTIENT_X_MPTR = 0x0e80;
    uint256 internal constant      QUOTIENT_Y_MPTR = 0x0ea0;
    uint256 internal constant          R_EVAL_MPTR = 0x0ec0;
    uint256 internal constant   PAIRING_LHS_X_MPTR = 0x0ee0;
    uint256 internal constant   PAIRING_LHS_Y_MPTR = 0x0f00;
    uint256 internal constant   PAIRING_RHS_X_MPTR = 0x0f20;
    uint256 internal constant   PAIRING_RHS_Y_MPTR = 0x0f40;

    function verifyProof(
        bytes calldata proof,
        uint256[] calldata instances
    ) public returns (bool) {
        assembly {
            // Read EC point (x, y) at (proof_cptr, proof_cptr + 0x20),
            // and check if the point is on affine plane,
            // and store them in (hash_mptr, hash_mptr + 0x20).
            // Return updated (success, proof_cptr, hash_mptr).
            function read_ec_point(success, proof_cptr, hash_mptr, q) -> ret0, ret1, ret2 {
                let x := calldataload(proof_cptr)
                let y := calldataload(add(proof_cptr, 0x20))
                ret0 := and(success, lt(x, q))
                ret0 := and(ret0, lt(y, q))
                ret0 := and(ret0, eq(mulmod(y, y, q), addmod(mulmod(x, mulmod(x, x, q), q), 3, q)))
                mstore(hash_mptr, x)
                mstore(add(hash_mptr, 0x20), y)
                ret1 := add(proof_cptr, 0x40)
                ret2 := add(hash_mptr, 0x40)
            }

            // Squeeze challenge by keccak256(memory[0..hash_mptr]),
            // and store hash mod r as challenge in challenge_mptr,
            // and push back hash in 0x00 as the first input for next squeeze.
            // Return updated (challenge_mptr, hash_mptr).
            function squeeze_challenge(challenge_mptr, hash_mptr, r) -> ret0, ret1 {
                let hash := keccak256(0x00, hash_mptr)
                mstore(challenge_mptr, mod(hash, r))
                mstore(0x00, hash)
                ret0 := add(challenge_mptr, 0x20)
                ret1 := 0x20
            }

            // Squeeze challenge without absorbing new input from calldata,
            // by putting an extra 0x01 in memory[0x20] and squeeze by keccak256(memory[0..21]),
            // and store hash mod r as challenge in challenge_mptr,
            // and push back hash in 0x00 as the first input for next squeeze.
            // Return updated (challenge_mptr).
            function squeeze_challenge_cont(challenge_mptr, r) -> ret {
                mstore8(0x20, 0x01)
                let hash := keccak256(0x00, 0x21)
                mstore(challenge_mptr, mod(hash, r))
                mstore(0x00, hash)
                ret := add(challenge_mptr, 0x20)
            }

            // Batch invert values in memory[mptr_start..mptr_end] in place.
            // Return updated (success).
            function batch_invert(success, mptr_start, mptr_end, r) -> ret {
                let gp_mptr := mptr_end
                let gp := mload(mptr_start)
                let mptr := add(mptr_start, 0x20)
                for
                    {}
                    lt(mptr, sub(mptr_end, 0x20))
                    {}
                {
                    gp := mulmod(gp, mload(mptr), r)
                    mstore(gp_mptr, gp)
                    mptr := add(mptr, 0x20)
                    gp_mptr := add(gp_mptr, 0x20)
                }
                gp := mulmod(gp, mload(mptr), r)

                mstore(gp_mptr, 0x20)
                mstore(add(gp_mptr, 0x20), 0x20)
                mstore(add(gp_mptr, 0x40), 0x20)
                mstore(add(gp_mptr, 0x60), gp)
                mstore(add(gp_mptr, 0x80), sub(r, 2))
                mstore(add(gp_mptr, 0xa0), r)
                ret := and(success, staticcall(gas(), 0x05, gp_mptr, 0xc0, gp_mptr, 0x20))
                let all_inv := mload(gp_mptr)

                let first_mptr := mptr_start
                let second_mptr := add(first_mptr, 0x20)
                gp_mptr := sub(gp_mptr, 0x20)
                for
                    {}
                    lt(second_mptr, mptr)
                    {}
                {
                    let inv := mulmod(all_inv, mload(gp_mptr), r)
                    all_inv := mulmod(all_inv, mload(mptr), r)
                    mstore(mptr, inv)
                    mptr := sub(mptr, 0x20)
                    gp_mptr := sub(gp_mptr, 0x20)
                }
                let inv_first := mulmod(all_inv, mload(second_mptr), r)
                let inv_second := mulmod(all_inv, mload(first_mptr), r)
                mstore(first_mptr, inv_first)
                mstore(second_mptr, inv_second)
            }

            // Add (x, y) into point at (0x00, 0x20).
            // Return updated (success).
            function ec_add_acc(success, x, y) -> ret {
                mstore(0x40, x)
                mstore(0x60, y)
                ret := and(success, staticcall(gas(), 0x06, 0x00, 0x80, 0x00, 0x40))
            }

            // Scale point at (0x00, 0x20) by scalar.
            function ec_mul_acc(success, scalar) -> ret {
                mstore(0x40, scalar)
                ret := and(success, staticcall(gas(), 0x07, 0x00, 0x60, 0x00, 0x40))
            }

            // Add (x, y) into point at (0x80, 0xa0).
            // Return updated (success).
            function ec_add_tmp(success, x, y) -> ret {
                mstore(0xc0, x)
                mstore(0xe0, y)
                ret := and(success, staticcall(gas(), 0x06, 0x80, 0x80, 0x80, 0x40))
            }

            // Scale point at (0x80, 0xa0) by scalar.
            // Return updated (success).
            function ec_mul_tmp(success, scalar) -> ret {
                mstore(0xc0, scalar)
                ret := and(success, staticcall(gas(), 0x07, 0x80, 0x60, 0x80, 0x40))
            }

            // Perform pairing check.
            // Return updated (success).
            function ec_pairing(success, lhs_x, lhs_y, rhs_x, rhs_y) -> ret {
                mstore(0x00, lhs_x)
                mstore(0x20, lhs_y)
                mstore(0x40, mload(G2_X_1_MPTR))
                mstore(0x60, mload(G2_X_2_MPTR))
                mstore(0x80, mload(G2_Y_1_MPTR))
                mstore(0xa0, mload(G2_Y_2_MPTR))
                mstore(0xc0, rhs_x)
                mstore(0xe0, rhs_y)
                mstore(0x100, mload(NEG_S_G2_X_1_MPTR))
                mstore(0x120, mload(NEG_S_G2_X_2_MPTR))
                mstore(0x140, mload(NEG_S_G2_Y_1_MPTR))
                mstore(0x160, mload(NEG_S_G2_Y_2_MPTR))
                ret := and(success, staticcall(gas(), 0x08, 0x00, 0x180, 0x00, 0x20))
                ret := and(ret, mload(0x00))
            }

            // Modulus
            let q := 21888242871839275222246405745257275088696311157297823662689037894645226208583 // BN254 base field
            let r := 21888242871839275222246405745257275088548364400416034343698204186575808495617 // BN254 scalar field

            // Initialize success as true
            let success := true

            {
                // Load vk_digest and num_instances of vk into memory
                mstore(0x0480, 0x0bf6795a71d16659495140c9d00f649ea6b77b8538bf1791ce28497654169e06) // vk_digest
                mstore(0x04a0, 0x0000000000000000000000000000000000000000000000000000000000000011) // num_instances

                // Check valid length of proof
                success := and(success, eq(0x0be0, calldataload(sub(PROOF_LEN_CPTR, 0x6014F51900))))

                // Check valid length of instances
                let num_instances := mload(NUM_INSTANCES_MPTR)
                success := and(success, eq(num_instances, calldataload(NUM_INSTANCE_CPTR)))

                // Absorb vk diegst
                mstore(0x00, mload(VK_DIGEST_MPTR))

                // Read instances and witness commitments and generate challenges
                let hash_mptr := 0x20
                let instance_cptr := INSTANCE_CPTR
                for
                    { let instance_cptr_end := add(instance_cptr, mul(0x20, num_instances)) }
                    lt(instance_cptr, instance_cptr_end)
                    {}
                {
                    let instance := calldataload(instance_cptr)
                    success := and(success, lt(instance, r))
                    mstore(hash_mptr, instance)
                    instance_cptr := add(instance_cptr, 0x20)
                    hash_mptr := add(hash_mptr, 0x20)
                }

                let proof_cptr := PROOF_CPTR
                let challenge_mptr := CHALLENGE_MPTR

                // Phase 1
                for
                    { let proof_cptr_end := add(proof_cptr, 0x0140) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q)
                }

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)

                // Phase 2
                for
                    { let proof_cptr_end := add(proof_cptr, 0x0140) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q)
                }

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)
                challenge_mptr := squeeze_challenge_cont(challenge_mptr, r)

                // Phase 3
                for
                    { let proof_cptr_end := add(proof_cptr, 0x0200) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q)
                }

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)

                // Phase 4
                for
                    { let proof_cptr_end := add(proof_cptr, 0x0100) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q)
                }

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)

                // Read evaluations
                for
                    { let proof_cptr_end := add(proof_cptr, 0x05e0) }
                    lt(proof_cptr, proof_cptr_end)
                    {}
                {
                    let eval := calldataload(proof_cptr)
                    success := and(success, lt(eval, r))
                    mstore(hash_mptr, eval)
                    proof_cptr := add(proof_cptr, 0x20)
                    hash_mptr := add(hash_mptr, 0x20)
                }

                // Read batch opening proof and generate challenges
                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)       // zeta
                challenge_mptr := squeeze_challenge_cont(challenge_mptr, r)                        // nu

                success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q) // W

                challenge_mptr, hash_mptr := squeeze_challenge(challenge_mptr, hash_mptr, r)       // mu

                success, proof_cptr, hash_mptr := read_ec_point(success, proof_cptr, hash_mptr, q) // W'

                // Load full vk into memory
                mstore(0x0480, 0x0bf6795a71d16659495140c9d00f649ea6b77b8538bf1791ce28497654169e06) // vk_digest
                mstore(0x04a0, 0x0000000000000000000000000000000000000000000000000000000000000011) // num_instances
                mstore(0x04c0, 0x0000000000000000000000000000000000000000000000000000000000000017) // k
                mstore(0x04e0, 0x30644e121894ba67550ff245e0f5eb5a25832df811e8df9dd100d30c2c14d821) // n_inv
                mstore(0x0500, 0x1283ba6f4b7b1a76ba2008fe823128bea4adb9269cbfd7c41c223be65bc60863) // omega
                mstore(0x0520, 0x1589862c1cf3f8b59954774980cc9361c568bcabd9cb7d0858de685794d4772b) // omega_inv
                mstore(0x0540, 0x2fffa2b50d66f628412d9782f09d3386d766a1168304babe2165fe7ec962e65b) // omega_inv_to_l
                mstore(0x0560, 0x0000000000000000000000000000000000000000000000000000000000000001) // has_accumulator
                mstore(0x0580, 0x0000000000000000000000000000000000000000000000000000000000000000) // acc_offset
                mstore(0x05a0, 0x0000000000000000000000000000000000000000000000000000000000000004) // num_acc_limbs
                mstore(0x05c0, 0x0000000000000000000000000000000000000000000000000000000000000044) // num_acc_limb_bits
                mstore(0x05e0, 0x0000000000000000000000000000000000000000000000000000000000000001) // g1_x
                mstore(0x0600, 0x0000000000000000000000000000000000000000000000000000000000000002) // g1_y
                mstore(0x0620, 0x198e9393920d483a7260bfb731fb5d25f1aa493335a9e71297e485b7aef312c2) // g2_x_1
                mstore(0x0640, 0x1800deef121f1e76426a00665e5c4479674322d4f75edadd46debd5cd992f6ed) // g2_x_2
                mstore(0x0660, 0x090689d0585ff075ec9e99ad690c3395bc4b313370b38ef355acdadcd122975b) // g2_y_1
                mstore(0x0680, 0x12c85ea5db8c6deb4aab71808dcb408fe3d1e7690c43d37b4ce6cc0166fa7daa) // g2_y_2
                mstore(0x06a0, 0x186282957db913abd99f91db59fe69922e95040603ef44c0bd7aa3adeef8f5ac) // neg_s_g2_x_1
                mstore(0x06c0, 0x17944351223333f260ddc3b4af45191b856689eda9eab5cbcddbbe570ce860d2) // neg_s_g2_x_2
                mstore(0x06e0, 0x06d971ff4a7467c3ec596ed6efc674572e32fd6f52b721f97e35b0b3d3546753) // neg_s_g2_y_1
                mstore(0x0700, 0x06ecdb9f9567f59ed2eee36e1e1d58797fd13cc97fafc2910f5e8a12f202fa9a) // neg_s_g2_y_2
                mstore(0x0720, 0x084f593eb49dac46e1f7120a308bd5dc39298d72d1bb9ae9218fa6ee6c9d46a5) // fixed_comms[0].x
                mstore(0x0740, 0x22b3c73e28580d7c8091060709d0dbffaf50b133d55bcb82519e77819106bdbd) // fixed_comms[0].y
                mstore(0x0760, 0x20d4c8f7e6f648fd565516fce8c364e171a9c1c073b878f751503c5cbd4a92c4) // fixed_comms[1].x
                mstore(0x0780, 0x1c5312a91b05597ea3ff1c4c1435b8883cfedbb36c02dbc9b94a45a19c6a198a) // fixed_comms[1].y
                mstore(0x07a0, 0x19a6d843ba63127e70c2886fb7901fa15e700dcff1c9256529f1e65735847cc2) // fixed_comms[2].x
                mstore(0x07c0, 0x27c5b63c956aefcd3941182cc75d8ce1a16c300d692b1e523d736117268afc8d) // fixed_comms[2].y
                mstore(0x07e0, 0x0791fca5fd76c0422ed9dfe35d3cc063512cefccacb0851b00e9a6c37c32fd3d) // fixed_comms[3].x
                mstore(0x0800, 0x2b2723263f4f836d4643759ac7a277a7743c5a752ebae09a4cbd2378e07e2bb8) // fixed_comms[3].y
                mstore(0x0820, 0x113782154a7cc059d479a98f94c0da104d5d75867dd0fee134347901168658e0) // fixed_comms[4].x
                mstore(0x0840, 0x23f22616d79a381006fe90b1e6dd92890b27f11f5a400ad49d5ffa2a6eef467f) // fixed_comms[4].y
                mstore(0x0860, 0x234845138c8f883e691ed30b7fd7449cf7f200b470cb4d657cff95eae285b87d) // fixed_comms[5].x
                mstore(0x0880, 0x2d7e8645d6062c3f8f61956e0940e8e72b65e36d4daf2d2d7d3b2020c88bc71b) // fixed_comms[5].y
                mstore(0x08a0, 0x05b47e365844cbd3823a1e4744f6af84aa80b9389279763dea5d58e9f5b6f6c3) // fixed_comms[6].x
                mstore(0x08c0, 0x0ddb65175110f3b681ab4b93aa324a4326abe14fef821e01294628f9b37c7c50) // fixed_comms[6].y
                mstore(0x08e0, 0x065ff526ded34e24a041b3d168138e43512b139f6cbde372802a2d655f07d3d3) // fixed_comms[7].x
                mstore(0x0900, 0x25fa5cffe4ddc6df39868665270c95679c39b6db9789af8f0ba1d8ae7f35b81b) // fixed_comms[7].y
                mstore(0x0920, 0x22b13fd2c5c6150e66bea3a60d4fdbabc41eb055aa4a9b9f3a15f5689da72e8c) // fixed_comms[8].x
                mstore(0x0940, 0x1074acccb36c7817ed4f985a2e17b3b8ed6165a0252d887c68bbaf4ac4055d1b) // fixed_comms[8].y
                mstore(0x0960, 0x140c450641755dc77abe404ce226d48f27e15ffd65bb85cd4bb0dd0896d5b341) // fixed_comms[9].x
                mstore(0x0980, 0x28c8fc18516838cde8e2642faa67774216d1f279dd38776428be69fe8394815b) // fixed_comms[9].y
                mstore(0x09a0, 0x1de84f037e6bf1d3bda00f51dca8036d8c23aac479033c2ca32a83a8167a1d78) // fixed_comms[10].x
                mstore(0x09c0, 0x2421813ff9cf27cfaaf45b911f4a57d35b96fe4cc0f47ffa57cba6ec230cf7d3) // fixed_comms[10].y
                mstore(0x09e0, 0x22b3f52aeb569f5aaa00fc77bdb39e6d5adf3b07ad0d2c07fe5d278a70e6d533) // fixed_comms[11].x
                mstore(0x0a00, 0x2ba41513ef460094c04429b185ff8f93f343cfc8c75859eef8ca485f357d524c) // fixed_comms[11].y
                mstore(0x0a20, 0x01b355d1be78a1d2a6a61135e28ce4548a82b03bce297a0362e8745ca87e0e8b) // fixed_comms[12].x
                mstore(0x0a40, 0x1ff8bde8a6bdf2f0d4bc56443b1115d525eac88034c0ae849c08a64f12125673) // fixed_comms[12].y
                mstore(0x0a60, 0x080cd04c85e20d0f1863e028d38eaaf194a9dc45e7b9cc60a65de9b23d730c6d) // fixed_comms[13].x
                mstore(0x0a80, 0x12a5470ff34a14d67d2a8e75edef914bc334bd1c00645a5a165d5e3041d1822c) // fixed_comms[13].y
                mstore(0x0aa0, 0x0f9d8d44926619e3b3f711cc497565f58e5f520cec456032de7792821079af97) // permutation_comms[0].x
                mstore(0x0ac0, 0x1e64d74fdd0268501d52d00fe6345f9d4b6816c4f31479a3d656d6cd445647e4) // permutation_comms[0].y
                mstore(0x0ae0, 0x2bbbb0fdd8a2d3af0c40639a8fc39fefe3c77c77a14bb4d5aaeabe4833eb240c) // permutation_comms[1].x
                mstore(0x0b00, 0x140c1dcbb437e091b34dc11148aad9e3ad45b442d9c154419d21c465786aba39) // permutation_comms[1].y
                mstore(0x0b20, 0x02fcf3df97bb5e5d381eb30f2f756d51b2c9cffe169f230c51fddbb0c85e5467) // permutation_comms[2].x
                mstore(0x0b40, 0x17342874b060c6a3bbf1058b0d837fe49e2dd026000cf4b3a2212b28e188f749) // permutation_comms[2].y
                mstore(0x0b60, 0x2684da5452099fa4c4a142badc78b665de1e80ec82aef7991a3b450753da5c8c) // permutation_comms[3].x
                mstore(0x0b80, 0x1b6f8df8f270297c01847eb1415984e70c4e8ff7d08172c4e876231073386146) // permutation_comms[3].y
                mstore(0x0ba0, 0x0242b3e8a833e6f4b311bce6bbbfacc0a657b830e17b5331feb3567775400c01) // permutation_comms[4].x
                mstore(0x0bc0, 0x0197d0c205d987ab271ac45dd7bb36ef68157b3ccd140d9d572d911ad26140c8) // permutation_comms[4].y
                mstore(0x0be0, 0x174d5a6c46d1d0e1bdfe495b3f006ea548772e0c352343220be2429f48b7e10b) // permutation_comms[5].x
                mstore(0x0c00, 0x27d18bfa0913d0d400011e11bf6ceb21a5fe5d398904f639046b47056bf5ae4f) // permutation_comms[5].y

                // Read accumulator from instances
                if mload(HAS_ACCUMULATOR_MPTR) {
                    let num_limbs := mload(NUM_ACC_LIMBS_MPTR)
                    let num_limb_bits := mload(NUM_ACC_LIMB_BITS_MPTR)

                    let cptr := add(INSTANCE_CPTR, mul(mload(ACC_OFFSET_MPTR), 0x20))
                    let lhs_y_off := mul(num_limbs, 0x20)
                    let rhs_x_off := mul(lhs_y_off, 2)
                    let rhs_y_off := mul(lhs_y_off, 3)
                    let lhs_x := calldataload(cptr)
                    let lhs_y := calldataload(add(cptr, lhs_y_off))
                    let rhs_x := calldataload(add(cptr, rhs_x_off))
                    let rhs_y := calldataload(add(cptr, rhs_y_off))
                    for
                        {
                            let cptr_end := add(cptr, mul(0x20, num_limbs))
                            let shift := num_limb_bits
                        }
                        lt(cptr, cptr_end)
                        {}
                    {
                        cptr := add(cptr, 0x20)
                        lhs_x := add(lhs_x, shl(shift, calldataload(cptr)))
                        lhs_y := add(lhs_y, shl(shift, calldataload(add(cptr, lhs_y_off))))
                        rhs_x := add(rhs_x, shl(shift, calldataload(add(cptr, rhs_x_off))))
                        rhs_y := add(rhs_y, shl(shift, calldataload(add(cptr, rhs_y_off))))
                        shift := add(shift, num_limb_bits)
                    }

                    success := and(success, eq(mulmod(lhs_y, lhs_y, q), addmod(mulmod(lhs_x, mulmod(lhs_x, lhs_x, q), q), 3, q)))
                    success := and(success, eq(mulmod(rhs_y, rhs_y, q), addmod(mulmod(rhs_x, mulmod(rhs_x, rhs_x, q), q), 3, q)))

                    mstore(ACC_LHS_X_MPTR, lhs_x)
                    mstore(ACC_LHS_Y_MPTR, lhs_y)
                    mstore(ACC_RHS_X_MPTR, rhs_x)
                    mstore(ACC_RHS_Y_MPTR, rhs_y)
                }

                pop(q)
            }

            // Revert earlier if anything from calldata is invalid
            if iszero(success) {
                revert(0, 0)
            }

            // Compute lagrange evaluations and instance evaluation
            {
                let k := mload(K_MPTR)
                let x := mload(X_MPTR)
                let x_n := x
                for
                    { let idx := 0 }
                    lt(idx, k)
                    { idx := add(idx, 1) }
                {
                    x_n := mulmod(x_n, x_n, r)
                }

                let omega := mload(OMEGA_MPTR)

                let mptr := X_N_MPTR
                let mptr_end := add(mptr, mul(0x20, add(mload(NUM_INSTANCES_MPTR), 6)))
                if iszero(mload(NUM_INSTANCES_MPTR)) {
                    mptr_end := add(mptr_end, 0x20)
                }
                for
                    { let pow_of_omega := mload(OMEGA_INV_TO_L_MPTR) }
                    lt(mptr, mptr_end)
                    { mptr := add(mptr, 0x20) }
                {
                    mstore(mptr, addmod(x, sub(r, pow_of_omega), r))
                    pow_of_omega := mulmod(pow_of_omega, omega, r)
                }
                let x_n_minus_1 := addmod(x_n, sub(r, 1), r)
                mstore(mptr_end, x_n_minus_1)
                success := batch_invert(success, X_N_MPTR, add(mptr_end, 0x20), r)

                mptr := X_N_MPTR
                let l_i_common := mulmod(x_n_minus_1, mload(N_INV_MPTR), r)
                for
                    { let pow_of_omega := mload(OMEGA_INV_TO_L_MPTR) }
                    lt(mptr, mptr_end)
                    { mptr := add(mptr, 0x20) }
                {
                    mstore(mptr, mulmod(l_i_common, mulmod(mload(mptr), pow_of_omega, r), r))
                    pow_of_omega := mulmod(pow_of_omega, omega, r)
                }

                let l_blind := mload(add(X_N_MPTR, 0x20))
                let l_i_cptr := add(X_N_MPTR, 0x40)
                for
                    { let l_i_cptr_end := add(X_N_MPTR, 0xc0) }
                    lt(l_i_cptr, l_i_cptr_end)
                    { l_i_cptr := add(l_i_cptr, 0x20) }
                {
                    l_blind := addmod(l_blind, mload(l_i_cptr), r)
                }

                let instance_eval := 0
                for
                    {
                        let instance_cptr := INSTANCE_CPTR
                        let instance_cptr_end := add(instance_cptr, mul(0x20, mload(NUM_INSTANCES_MPTR)))
                    }
                    lt(instance_cptr, instance_cptr_end)
                    {
                        instance_cptr := add(instance_cptr, 0x20)
                        l_i_cptr := add(l_i_cptr, 0x20)
                    }
                {
                    instance_eval := addmod(instance_eval, mulmod(mload(l_i_cptr), calldataload(instance_cptr), r), r)
                }

                let x_n_minus_1_inv := mload(mptr_end)
                let l_last := mload(X_N_MPTR)
                let l_0 := mload(add(X_N_MPTR, 0xc0))

                mstore(X_N_MPTR, x_n)
                mstore(X_N_MINUS_1_INV_MPTR, x_n_minus_1_inv)
                mstore(L_LAST_MPTR, l_last)
                mstore(L_BLIND_MPTR, l_blind)
                mstore(L_0_MPTR, l_0)
                mstore(INSTANCE_EVAL_MPTR, instance_eval)
            }

            // Compute quotient evavluation
            {
                let quotient_eval_numer
                let delta := 4131629893567559867359510883348571134090853742863529169391034518566172092834
                let y := mload(Y_MPTR)
                {
                    let a_0 := calldataload(0x05e4)
                    let f_0 := calldataload(0x06a4)
                    let var0 := mulmod(a_0, f_0, r)
                    let a_1 := calldataload(0x0604)
                    let f_1 := calldataload(0x06c4)
                    let var1 := mulmod(a_1, f_1, r)
                    let var2 := addmod(var0, var1, r)
                    let a_2 := calldataload(0x0624)
                    let f_2 := calldataload(0x06e4)
                    let var3 := mulmod(a_2, f_2, r)
                    let var4 := addmod(var2, var3, r)
                    let a_3 := calldataload(0x0644)
                    let f_3 := calldataload(0x0704)
                    let var5 := mulmod(a_3, f_3, r)
                    let var6 := addmod(var4, var5, r)
                    let a_4 := calldataload(0x0664)
                    let f_4 := calldataload(0x0724)
                    let var7 := mulmod(a_4, f_4, r)
                    let var8 := addmod(var6, var7, r)
                    let var9 := mulmod(a_0, a_1, r)
                    let f_5 := calldataload(0x0764)
                    let var10 := mulmod(var9, f_5, r)
                    let var11 := addmod(var8, var10, r)
                    let var12 := mulmod(a_2, a_3, r)
                    let f_6 := calldataload(0x0784)
                    let var13 := mulmod(var12, f_6, r)
                    let var14 := addmod(var11, var13, r)
                    let f_7 := calldataload(0x0744)
                    let a_4_next_1 := calldataload(0x0684)
                    let var15 := mulmod(f_7, a_4_next_1, r)
                    let var16 := addmod(var14, var15, r)
                    let f_8 := calldataload(0x07a4)
                    let var17 := addmod(var16, f_8, r)
                    quotient_eval_numer := var17
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := addmod(l_0, sub(r, mulmod(l_0, calldataload(0x0944), r)), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let perm_z_last := calldataload(0x09a4)
                    let eval := mulmod(mload(L_LAST_MPTR), addmod(mulmod(perm_z_last, perm_z_last, r), sub(r, perm_z_last), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let eval := mulmod(mload(L_0_MPTR), addmod(calldataload(0x09a4), sub(r, calldataload(0x0984)), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x0964)
                    let rhs := calldataload(0x0944)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x05e4), mulmod(beta, calldataload(0x0884), r), r), gamma, r), r)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0604), mulmod(beta, calldataload(0x08a4), r), r), gamma, r), r)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0624), mulmod(beta, calldataload(0x08c4), r), r), gamma, r), r)
                    mstore(0x00, mulmod(beta, mload(X_MPTR), r))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x05e4), mload(0x00), r), gamma, r), r)
                    mstore(0x00, mulmod(mload(0x00), delta, r))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0604), mload(0x00), r), gamma, r), r)
                    mstore(0x00, mulmod(mload(0x00), delta, r))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0624), mload(0x00), r), gamma, r), r)
                    mstore(0x00, mulmod(mload(0x00), delta, r))
                    let left_sub_right := addmod(lhs, sub(r, rhs), r)
                    let eval := addmod(left_sub_right, sub(r, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), r), r)), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let gamma := mload(GAMMA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let lhs := calldataload(0x09c4)
                    let rhs := calldataload(0x09a4)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0644), mulmod(beta, calldataload(0x08e4), r), r), gamma, r), r)
                    lhs := mulmod(lhs, addmod(addmod(calldataload(0x0664), mulmod(beta, calldataload(0x0904), r), r), gamma, r), r)
                    lhs := mulmod(lhs, addmod(addmod(mload(INSTANCE_EVAL_MPTR), mulmod(beta, calldataload(0x0924), r), r), gamma, r), r)
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0644), mload(0x00), r), gamma, r), r)
                    mstore(0x00, mulmod(mload(0x00), delta, r))
                    rhs := mulmod(rhs, addmod(addmod(calldataload(0x0664), mload(0x00), r), gamma, r), r)
                    mstore(0x00, mulmod(mload(0x00), delta, r))
                    rhs := mulmod(rhs, addmod(addmod(mload(INSTANCE_EVAL_MPTR), mload(0x00), r), gamma, r), r)
                    let left_sub_right := addmod(lhs, sub(r, rhs), r)
                    let eval := addmod(left_sub_right, sub(r, mulmod(left_sub_right, addmod(mload(L_LAST_MPTR), mload(L_BLIND_MPTR), r), r)), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x09e4), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x09e4), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_9 := calldataload(0x07c4)
                        let f_10 := calldataload(0x07e4)
                        table := f_9
                        table := addmod(mulmod(table, theta, r), f_10, r)
                        table := addmod(table, beta, r)
                    }
                    let input_0
                    {
                        let f_12 := calldataload(0x0824)
                        let var0 := 0x5
                        let var1 := mulmod(f_12, var0, r)
                        let a_0 := calldataload(0x05e4)
                        let var2 := mulmod(f_12, a_0, r)
                        input_0 := var1
                        input_0 := addmod(mulmod(input_0, theta, r), var2, r)
                        input_0 := addmod(input_0, beta, r)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(r, mulmod(calldataload(0x0a24), tmp, r)), r)
                        lhs := mulmod(mulmod(table, tmp, r), addmod(calldataload(0x0a04), sub(r, calldataload(0x09e4)), r), r)
                    }
                    let eval := mulmod(addmod(1, sub(r, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), r)), r), addmod(lhs, sub(r, rhs), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x0a44), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x0a44), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_9 := calldataload(0x07c4)
                        let f_10 := calldataload(0x07e4)
                        table := f_9
                        table := addmod(mulmod(table, theta, r), f_10, r)
                        table := addmod(table, beta, r)
                    }
                    let input_0
                    {
                        let f_12 := calldataload(0x0824)
                        let var0 := 0x5
                        let var1 := mulmod(f_12, var0, r)
                        let a_1 := calldataload(0x0604)
                        let var2 := mulmod(f_12, a_1, r)
                        input_0 := var1
                        input_0 := addmod(mulmod(input_0, theta, r), var2, r)
                        input_0 := addmod(input_0, beta, r)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(r, mulmod(calldataload(0x0a84), tmp, r)), r)
                        lhs := mulmod(mulmod(table, tmp, r), addmod(calldataload(0x0a64), sub(r, calldataload(0x0a44)), r), r)
                    }
                    let eval := mulmod(addmod(1, sub(r, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), r)), r), addmod(lhs, sub(r, rhs), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x0aa4), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x0aa4), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_9 := calldataload(0x07c4)
                        let f_10 := calldataload(0x07e4)
                        table := f_9
                        table := addmod(mulmod(table, theta, r), f_10, r)
                        table := addmod(table, beta, r)
                    }
                    let input_0
                    {
                        let f_12 := calldataload(0x0824)
                        let var0 := 0x5
                        let var1 := mulmod(f_12, var0, r)
                        let a_2 := calldataload(0x0624)
                        let var2 := mulmod(f_12, a_2, r)
                        input_0 := var1
                        input_0 := addmod(mulmod(input_0, theta, r), var2, r)
                        input_0 := addmod(input_0, beta, r)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(r, mulmod(calldataload(0x0ae4), tmp, r)), r)
                        lhs := mulmod(mulmod(table, tmp, r), addmod(calldataload(0x0ac4), sub(r, calldataload(0x0aa4)), r), r)
                    }
                    let eval := mulmod(addmod(1, sub(r, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), r)), r), addmod(lhs, sub(r, rhs), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x0b04), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x0b04), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_9 := calldataload(0x07c4)
                        let f_10 := calldataload(0x07e4)
                        table := f_9
                        table := addmod(mulmod(table, theta, r), f_10, r)
                        table := addmod(table, beta, r)
                    }
                    let input_0
                    {
                        let f_12 := calldataload(0x0824)
                        let var0 := 0x5
                        let var1 := mulmod(f_12, var0, r)
                        let a_3 := calldataload(0x0644)
                        let var2 := mulmod(f_12, a_3, r)
                        input_0 := var1
                        input_0 := addmod(mulmod(input_0, theta, r), var2, r)
                        input_0 := addmod(input_0, beta, r)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(r, mulmod(calldataload(0x0b44), tmp, r)), r)
                        lhs := mulmod(mulmod(table, tmp, r), addmod(calldataload(0x0b24), sub(r, calldataload(0x0b04)), r), r)
                    }
                    let eval := mulmod(addmod(1, sub(r, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), r)), r), addmod(lhs, sub(r, rhs), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_0 := mload(L_0_MPTR)
                    let eval := mulmod(l_0, calldataload(0x0b64), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let l_last := mload(L_LAST_MPTR)
                    let eval := mulmod(l_last, calldataload(0x0b64), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }
                {
                    let theta := mload(THETA_MPTR)
                    let beta := mload(BETA_MPTR)
                    let table
                    {
                        let f_9 := calldataload(0x07c4)
                        let f_10 := calldataload(0x07e4)
                        table := f_9
                        table := addmod(mulmod(table, theta, r), f_10, r)
                        table := addmod(table, beta, r)
                    }
                    let input_0
                    {
                        let f_11 := calldataload(0x0804)
                        let f_13 := calldataload(0x0844)
                        let a_0 := calldataload(0x05e4)
                        let var0 := mulmod(f_13, a_0, r)
                        input_0 := f_11
                        input_0 := addmod(mulmod(input_0, theta, r), var0, r)
                        input_0 := addmod(input_0, beta, r)
                    }
                    let lhs
                    let rhs
                    rhs := table
                    {
                        let tmp := input_0
                        rhs := addmod(rhs, sub(r, mulmod(calldataload(0x0ba4), tmp, r)), r)
                        lhs := mulmod(mulmod(table, tmp, r), addmod(calldataload(0x0b84), sub(r, calldataload(0x0b64)), r), r)
                    }
                    let eval := mulmod(addmod(1, sub(r, addmod(mload(L_BLIND_MPTR), mload(L_LAST_MPTR), r)), r), addmod(lhs, sub(r, rhs), r), r)
                    quotient_eval_numer := addmod(mulmod(quotient_eval_numer, y, r), eval, r)
                }

                pop(y)
                pop(delta)

                let quotient_eval := mulmod(quotient_eval_numer, mload(X_N_MINUS_1_INV_MPTR), r)
                mstore(QUOTIENT_EVAL_MPTR, quotient_eval)
            }

            // Compute quotient commitment
            {
                mstore(0x00, calldataload(LAST_QUOTIENT_X_CPTR))
                mstore(0x20, calldataload(add(LAST_QUOTIENT_X_CPTR, 0x20)))
                let x_n := mload(X_N_MPTR)
                for
                    {
                        let cptr := sub(LAST_QUOTIENT_X_CPTR, 0x40)
                        let cptr_end := sub(FIRST_QUOTIENT_X_CPTR, 0x40)
                    }
                    lt(cptr_end, cptr)
                    {}
                {
                    success := ec_mul_acc(success, x_n)
                    success := ec_add_acc(success, calldataload(cptr), calldataload(add(cptr, 0x20)))
                    cptr := sub(cptr, 0x40)
                }
                mstore(QUOTIENT_X_MPTR, mload(0x00))
                mstore(QUOTIENT_Y_MPTR, mload(0x20))
            }

            // Compute pairing lhs and rhs
            {
                {
                    let x := mload(X_MPTR)
                    let omega := mload(OMEGA_MPTR)
                    let omega_inv := mload(OMEGA_INV_MPTR)
                    let x_pow_of_omega := mulmod(x, omega, r)
                    mstore(0x02c0, x_pow_of_omega)
                    mstore(0x02a0, x)
                    x_pow_of_omega := mulmod(x, omega_inv, r)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, r)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, r)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, r)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, r)
                    x_pow_of_omega := mulmod(x_pow_of_omega, omega_inv, r)
                    mstore(0x0280, x_pow_of_omega)
                }
                {
                    let mu := mload(MU_MPTR)
                    for
                        {
                            let mptr := 0x02e0
                            let mptr_end := 0x0340
                            let point_mptr := 0x0280
                        }
                        lt(mptr, mptr_end)
                        {
                            mptr := add(mptr, 0x20)
                            point_mptr := add(point_mptr, 0x20)
                        }
                    {
                        mstore(mptr, addmod(mu, sub(r, mload(point_mptr)), r))
                    }
                    let s
                    s := mload(0x0300)
                    mstore(0x0340, s)
                    let diff
                    diff := mload(0x02e0)
                    diff := mulmod(diff, mload(0x0320), r)
                    mstore(0x0360, diff)
                    mstore(0x00, diff)
                    diff := mload(0x02e0)
                    mstore(0x0380, diff)
                    diff := 1
                    mstore(0x03a0, diff)
                }
                {
                    let point_1 := mload(0x02a0)
                    let coeff
                    coeff := 1
                    coeff := mulmod(coeff, mload(0x0300), r)
                    mstore(0x20, coeff)
                }
                {
                    let point_1 := mload(0x02a0)
                    let point_2 := mload(0x02c0)
                    let coeff
                    coeff := addmod(point_1, sub(r, point_2), r)
                    coeff := mulmod(coeff, mload(0x0300), r)
                    mstore(0x40, coeff)
                    coeff := addmod(point_2, sub(r, point_1), r)
                    coeff := mulmod(coeff, mload(0x0320), r)
                    mstore(0x60, coeff)
                }
                {
                    let point_0 := mload(0x0280)
                    let point_1 := mload(0x02a0)
                    let point_2 := mload(0x02c0)
                    let coeff
                    coeff := addmod(point_0, sub(r, point_1), r)
                    coeff := mulmod(coeff, addmod(point_0, sub(r, point_2), r), r)
                    coeff := mulmod(coeff, mload(0x02e0), r)
                    mstore(0x80, coeff)
                    coeff := addmod(point_1, sub(r, point_0), r)
                    coeff := mulmod(coeff, addmod(point_1, sub(r, point_2), r), r)
                    coeff := mulmod(coeff, mload(0x0300), r)
                    mstore(0xa0, coeff)
                    coeff := addmod(point_2, sub(r, point_0), r)
                    coeff := mulmod(coeff, addmod(point_2, sub(r, point_1), r), r)
                    coeff := mulmod(coeff, mload(0x0320), r)
                    mstore(0xc0, coeff)
                }
                {
                    success := batch_invert(success, 0, 0xe0, r)
                    let diff_0_inv := mload(0x00)
                    mstore(0x0360, diff_0_inv)
                    for
                        {
                            let mptr := 0x0380
                            let mptr_end := 0x03c0
                        }
                        lt(mptr, mptr_end)
                        { mptr := add(mptr, 0x20) }
                    {
                        mstore(mptr, mulmod(mload(mptr), diff_0_inv, r))
                    }
                }
                {
                    let coeff := mload(0x20)
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x0864), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(coeff, mload(QUOTIENT_EVAL_MPTR), r), r)
                    for
                        {
                            let mptr := 0x0924
                            let mptr_end := 0x0864
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x20) }
                    {
                        r_eval := addmod(mulmod(r_eval, zeta, r), mulmod(coeff, calldataload(mptr), r), r)
                    }
                    for
                        {
                            let mptr := 0x0844
                            let mptr_end := 0x0684
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x20) }
                    {
                        r_eval := addmod(mulmod(r_eval, zeta, r), mulmod(coeff, calldataload(mptr), r), r)
                    }
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x0ba4), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x0b44), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x0ae4), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x0a84), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(coeff, calldataload(0x0a24), r), r)
                    for
                        {
                            let mptr := 0x0644
                            let mptr_end := 0x05c4
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x20) }
                    {
                        r_eval := addmod(mulmod(r_eval, zeta, r), mulmod(coeff, calldataload(mptr), r), r)
                    }
                    mstore(0x03c0, r_eval)
                }
                {
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(mload(0x40), calldataload(0x0b64), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x60), calldataload(0x0b84), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0x40), calldataload(0x0b04), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x60), calldataload(0x0b24), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0x40), calldataload(0x0aa4), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x60), calldataload(0x0ac4), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0x40), calldataload(0x0a44), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x60), calldataload(0x0a64), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0x40), calldataload(0x09e4), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x60), calldataload(0x0a04), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0x40), calldataload(0x09a4), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x60), calldataload(0x09c4), r), r)
                    r_eval := mulmod(r_eval, zeta, r)
                    r_eval := addmod(r_eval, mulmod(mload(0x40), calldataload(0x0664), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0x60), calldataload(0x0684), r), r)
                    r_eval := mulmod(r_eval, mload(0x0380), r)
                    mstore(0x03e0, r_eval)
                }
                {
                    let zeta := mload(ZETA_MPTR)
                    let r_eval := 0
                    r_eval := addmod(r_eval, mulmod(mload(0x80), calldataload(0x0984), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0xa0), calldataload(0x0944), r), r)
                    r_eval := addmod(r_eval, mulmod(mload(0xc0), calldataload(0x0964), r), r)
                    r_eval := mulmod(r_eval, mload(0x03a0), r)
                    mstore(0x0400, r_eval)
                }
                {
                    let sum := mload(0x20)
                    mstore(0x0420, sum)
                }
                {
                    let sum := mload(0x40)
                    sum := addmod(sum, mload(0x60), r)
                    mstore(0x0440, sum)
                }
                {
                    let sum := mload(0x80)
                    sum := addmod(sum, mload(0xa0), r)
                    sum := addmod(sum, mload(0xc0), r)
                    mstore(0x0460, sum)
                }
                {
                    for
                        {
                            let mptr := 0x00
                            let mptr_end := 0x60
                            let sum_mptr := 0x0420
                        }
                        lt(mptr, mptr_end)
                        {
                            mptr := add(mptr, 0x20)
                            sum_mptr := add(sum_mptr, 0x20)
                        }
                    {
                        mstore(mptr, mload(sum_mptr))
                    }
                    success := batch_invert(success, 0, 0x60, r)
                    let r_eval := mulmod(mload(0x40), mload(0x0400), r)
                    for
                        {
                            let sum_inv_mptr := 0x20
                            let sum_inv_mptr_end := 0x60
                            let r_eval_mptr := 0x03e0
                        }
                        lt(sum_inv_mptr, sum_inv_mptr_end)
                        {
                            sum_inv_mptr := sub(sum_inv_mptr, 0x20)
                            r_eval_mptr := sub(r_eval_mptr, 0x20)
                        }
                    {
                        r_eval := mulmod(r_eval, mload(NU_MPTR), r)
                        r_eval := addmod(r_eval, mulmod(mload(sum_inv_mptr), mload(r_eval_mptr), r), r)
                    }
                    mstore(R_EVAL_MPTR, r_eval)
                }
                {
                    let nu := mload(NU_MPTR)
                    mstore(0x00, calldataload(0x04a4))
                    mstore(0x20, calldataload(0x04c4))
                    success := ec_mul_acc(success, mload(ZETA_MPTR))
                    success := ec_add_acc(success, mload(QUOTIENT_X_MPTR), mload(QUOTIENT_Y_MPTR))
                    for
                        {
                            let mptr := 0x0be0
                            let mptr_end := 0x08e0
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x40) }
                    {
                        success := ec_mul_acc(success, mload(ZETA_MPTR))
                        success := ec_add_acc(success, mload(mptr), mload(add(mptr, 0x20)))
                    }
                    success := ec_mul_acc(success, mload(ZETA_MPTR))
                    success := ec_add_acc(success, mload(0x08a0), mload(0x08c0))
                    success := ec_mul_acc(success, mload(ZETA_MPTR))
                    success := ec_add_acc(success, mload(0x0860), mload(0x0880))
                    success := ec_mul_acc(success, mload(ZETA_MPTR))
                    success := ec_add_acc(success, mload(0x08e0), mload(0x0900))
                    for
                        {
                            let mptr := 0x0820
                            let mptr_end := 0x06e0
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x40) }
                    {
                        success := ec_mul_acc(success, mload(ZETA_MPTR))
                        success := ec_add_acc(success, mload(mptr), mload(add(mptr, 0x20)))
                    }
                    for
                        {
                            let mptr := 0x02a4
                            let mptr_end := 0x0164
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x40) }
                    {
                        success := ec_mul_acc(success, mload(ZETA_MPTR))
                        success := ec_add_acc(success, calldataload(mptr), calldataload(add(mptr, 0x20)))
                    }
                    for
                        {
                            let mptr := 0x0124
                            let mptr_end := 0x24
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x40) }
                    {
                        success := ec_mul_acc(success, mload(ZETA_MPTR))
                        success := ec_add_acc(success, calldataload(mptr), calldataload(add(mptr, 0x20)))
                    }
                    mstore(0x80, calldataload(0x0464))
                    mstore(0xa0, calldataload(0x0484))
                    for
                        {
                            let mptr := 0x0424
                            let mptr_end := 0x02e4
                        }
                        lt(mptr_end, mptr)
                        { mptr := sub(mptr, 0x40) }
                    {
                        success := ec_mul_tmp(success, mload(ZETA_MPTR))
                        success := ec_add_tmp(success, calldataload(mptr), calldataload(add(mptr, 0x20)))
                    }
                    success := ec_mul_tmp(success, mload(ZETA_MPTR))
                    success := ec_add_tmp(success, calldataload(0x0164), calldataload(0x0184))
                    success := ec_mul_tmp(success, mulmod(nu, mload(0x0380), r))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    nu := mulmod(nu, mload(NU_MPTR), r)
                    mstore(0x80, calldataload(0x02e4))
                    mstore(0xa0, calldataload(0x0304))
                    success := ec_mul_tmp(success, mulmod(nu, mload(0x03a0), r))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(0x80, mload(G1_X_MPTR))
                    mstore(0xa0, mload(G1_Y_MPTR))
                    success := ec_mul_tmp(success, sub(r, mload(R_EVAL_MPTR)))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(0x80, calldataload(0x0bc4))
                    mstore(0xa0, calldataload(0x0be4))
                    success := ec_mul_tmp(success, sub(r, mload(0x0340)))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(0x80, calldataload(0x0c04))
                    mstore(0xa0, calldataload(0x0c24))
                    success := ec_mul_tmp(success, mload(MU_MPTR))
                    success := ec_add_acc(success, mload(0x80), mload(0xa0))
                    mstore(PAIRING_LHS_X_MPTR, mload(0x00))
                    mstore(PAIRING_LHS_Y_MPTR, mload(0x20))
                    mstore(PAIRING_RHS_X_MPTR, calldataload(0x0c04))
                    mstore(PAIRING_RHS_Y_MPTR, calldataload(0x0c24))
                }
            }

            // Random linear combine with accumulator
            if mload(HAS_ACCUMULATOR_MPTR) {
                mstore(0x00, mload(ACC_LHS_X_MPTR))
                mstore(0x20, mload(ACC_LHS_Y_MPTR))
                mstore(0x40, mload(ACC_RHS_X_MPTR))
                mstore(0x60, mload(ACC_RHS_Y_MPTR))
                mstore(0x80, mload(PAIRING_LHS_X_MPTR))
                mstore(0xa0, mload(PAIRING_LHS_Y_MPTR))
                mstore(0xc0, mload(PAIRING_RHS_X_MPTR))
                mstore(0xe0, mload(PAIRING_RHS_Y_MPTR))
                let challenge := mod(keccak256(0x00, 0x100), r)

                // [pairing_lhs] += challenge * [acc_lhs]
                success := ec_mul_acc(success, challenge)
                success := ec_add_acc(success, mload(PAIRING_LHS_X_MPTR), mload(PAIRING_LHS_Y_MPTR))
                mstore(PAIRING_LHS_X_MPTR, mload(0x00))
                mstore(PAIRING_LHS_Y_MPTR, mload(0x20))

                // [pairing_rhs] += challenge * [acc_rhs]
                mstore(0x00, mload(ACC_RHS_X_MPTR))
                mstore(0x20, mload(ACC_RHS_Y_MPTR))
                success := ec_mul_acc(success, challenge)
                success := ec_add_acc(success, mload(PAIRING_RHS_X_MPTR), mload(PAIRING_RHS_Y_MPTR))
                mstore(PAIRING_RHS_X_MPTR, mload(0x00))
                mstore(PAIRING_RHS_Y_MPTR, mload(0x20))
            }

            // Perform pairing
            success := ec_pairing(
                success,
                mload(PAIRING_LHS_X_MPTR),
                mload(PAIRING_LHS_Y_MPTR),
                mload(PAIRING_RHS_X_MPTR),
                mload(PAIRING_RHS_Y_MPTR)
            )

            // Revert if anything fails
            if iszero(success) {
                revert(0x00, 0x00)
            }

            // Return 1 as result if everything succeeds
            mstore(0x00, 1)
            return(0x00, 0x20)
        }
    }
}