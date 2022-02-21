// This file is MIT Licensed.
//
// Copyright 2017 Christian Reitwiessner
// Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
// The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
pragma solidity ^0.8.0;
library Pairing {
    struct G1Point {
        uint X;
        uint Y;
    }
    // Encoding of field elements is: X[0] * z + X[1]
    struct G2Point {
        uint[2] X;
        uint[2] Y;
    }
    /// @return the generator of G1
    function P1() pure internal returns (G1Point memory) {
        return G1Point(1, 2);
    }
    /// @return the generator of G2
    function P2() pure internal returns (G2Point memory) {
        return G2Point(
            [10857046999023057135944570762232829481370756359578518086990519993285655852781,
             11559732032986387107991004021392285783925812861821192530917403151452391805634],
            [8495653923123431417604973247489272438418190587263600148770280649306958101930,
             4082367875863433681332203403145435568316851327593401208105741076214120093531]
        );
    }
    /// @return the negation of p, i.e. p.addition(p.negate()) should be zero.
    function negate(G1Point memory p) pure internal returns (G1Point memory) {
        // The prime q in the base field F_q for G1
        uint q = 21888242871839275222246405745257275088696311157297823662689037894645226208583;
        if (p.X == 0 && p.Y == 0)
            return G1Point(0, 0);
        return G1Point(p.X, q - (p.Y % q));
    }
    /// @return r the sum of two points of G1
    function addition(G1Point memory p1, G1Point memory p2) internal view returns (G1Point memory r) {
        uint[4] memory input;
        input[0] = p1.X;
        input[1] = p1.Y;
        input[2] = p2.X;
        input[3] = p2.Y;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 6, input, 0xc0, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
    }


    /// @return r the product of a point on G1 and a scalar, i.e.
    /// p == p.scalar_mul(1) and p.addition(p) == p.scalar_mul(2) for all points p.
    function scalar_mul(G1Point memory p, uint s) internal view returns (G1Point memory r) {
        uint[3] memory input;
        input[0] = p.X;
        input[1] = p.Y;
        input[2] = s;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 7, input, 0x80, r, 0x60)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require (success);
    }
    /// @return the result of computing the pairing check
    /// e(p1[0], p2[0]) *  .... * e(p1[n], p2[n]) == 1
    /// For example pairing([P1(), P1().negate()], [P2(), P2()]) should
    /// return true.
    function pairing(G1Point[] memory p1, G2Point[] memory p2) internal view returns (bool) {
        require(p1.length == p2.length);
        uint elements = p1.length;
        uint inputSize = elements * 6;
        uint[] memory input = new uint[](inputSize);
        for (uint i = 0; i < elements; i++)
        {
            input[i * 6 + 0] = p1[i].X;
            input[i * 6 + 1] = p1[i].Y;
            input[i * 6 + 2] = p2[i].X[1];
            input[i * 6 + 3] = p2[i].X[0];
            input[i * 6 + 4] = p2[i].Y[1];
            input[i * 6 + 5] = p2[i].Y[0];
        }
        uint[1] memory out;
        bool success;
        assembly {
            success := staticcall(sub(gas(), 2000), 8, add(input, 0x20), mul(inputSize, 0x20), out, 0x20)
            // Use "invalid" to make gas estimation work
            switch success case 0 { invalid() }
        }
        require(success);
        return out[0] != 0;
    }
    /// Convenience method for a pairing check for two pairs.
    function pairingProd2(G1Point memory a1, G2Point memory a2, G1Point memory b1, G2Point memory b2) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](2);
        G2Point[] memory p2 = new G2Point[](2);
        p1[0] = a1;
        p1[1] = b1;
        p2[0] = a2;
        p2[1] = b2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for three pairs.
    function pairingProd3(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](3);
        G2Point[] memory p2 = new G2Point[](3);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        return pairing(p1, p2);
    }
    /// Convenience method for a pairing check for four pairs.
    function pairingProd4(
            G1Point memory a1, G2Point memory a2,
            G1Point memory b1, G2Point memory b2,
            G1Point memory c1, G2Point memory c2,
            G1Point memory d1, G2Point memory d2
    ) internal view returns (bool) {
        G1Point[] memory p1 = new G1Point[](4);
        G2Point[] memory p2 = new G2Point[](4);
        p1[0] = a1;
        p1[1] = b1;
        p1[2] = c1;
        p1[3] = d1;
        p2[0] = a2;
        p2[1] = b2;
        p2[2] = c2;
        p2[3] = d2;
        return pairing(p1, p2);
    }
}

contract Verifier {
    using Pairing for *;
    struct VerifyingKey {
        Pairing.G1Point alpha;
        Pairing.G2Point beta;
        Pairing.G2Point gamma;
        Pairing.G2Point delta;
        Pairing.G1Point[] gamma_abc;
    }
    struct Proof {
        Pairing.G1Point a;
        Pairing.G2Point b;
        Pairing.G1Point c;
    }

    public bytes32 roothash;

    constructor(bytes32 _rootHash) {
        rootHash = _rootHash;
    }

    function verifyingKey() pure internal returns (VerifyingKey memory vk) {
        vk.alpha = Pairing.G1Point(uint256(0x22b6ca0d050090a19684a30a7bef73dd803a9e13e2fbd8c00f999a3e8f6a2f86), uint256(0x1dfb15013fbe37a737507b24a4c7269560d56bf7d87b8952d31bf89b8e6046a0));
        vk.beta = Pairing.G2Point([uint256(0x29575191c5e55db8a356aa20d67011e13fb5759b26b505785c088b2a918c07e7), uint256(0x1f86f1540256a6d48f6a6343b2ccb8960bfffb6656cb36de5aceabfd2a203d06)], [uint256(0x08ab4e7bbc4b2db9d7d2990d848ac0c4102ef9454a239161293b813a938dac51), uint256(0x0a7fcc697907ec4475c225b7e294d429e763a7d895e1bd2a8609ea0c84f7751b)]);
        vk.gamma = Pairing.G2Point([uint256(0x1ed4adba760cdab67a184d273af98af897c9824d5077863318b9dbdf51c0794d), uint256(0x19c5ac41432283365e079d0a8774e9c0eb91dba32be1fe5e0a6dc8cda58496f7)], [uint256(0x2cfdf8690738e5de7c3275bafc579c2ad82aad3bdf6b7c34eef0575439b578ae), uint256(0x2f0d3833be0a1109212ef69b6ec918c1315144c35da7547d99d3241791960b9f)]);
        vk.delta = Pairing.G2Point([uint256(0x073f0911a1f69f43fdc1f164c32c3c3faad09976087552677de4978bfa988da0), uint256(0x1b60d9d9fd88e7db7bd5dec1712e981e5384259ecad09c8aeea934c9f49f4fdf)], [uint256(0x2cfa7a344998f5bae5d63aad1260403caf030ce78fb5f1d72494b65b6cd3f44d), uint256(0x04b0af18f9a43eecc612be3519009035f80033f19076ac4154e03571ec30b7cc)]);
        vk.gamma_abc = new Pairing.G1Point[](20);
        vk.gamma_abc[0] = Pairing.G1Point(uint256(0x09a2adda355f43bef1d6c01dd0139e10333a15e242a5d0cc5a87e1d8bbf1b09c), uint256(0x17952759280e79500d21243dfd6347237878b3e080df222e8e2f986421fcc155));
        vk.gamma_abc[1] = Pairing.G1Point(uint256(0x24d7e4f462f1f1140bc246fc7a07bd055502cb6107b734b8f6a1c54e31b7b670), uint256(0x06f7de31629e2b0a0bdc6169dfa39db2611ac5835f934011300e930a4ab46295));
        vk.gamma_abc[2] = Pairing.G1Point(uint256(0x01ddf1b676d1e53fb8566b462cb9dc8de8bdb735a6b2471c7ec09538cbb1c567), uint256(0x25066a7edcd94ec2de2ce9f43d648a55f427a895b3fd9bdfd277b248ba24c698));
        vk.gamma_abc[3] = Pairing.G1Point(uint256(0x26491380dc41c8e0697c3656bdec7856014be8bf78f6ddf0f6ef7c17645f8357), uint256(0x2365e71b38af3de3391798b37fa335e91f095d262f125f97dad27cbc989d09d1));
        vk.gamma_abc[4] = Pairing.G1Point(uint256(0x0a2d208be2a7b3b88cb98d770331f2fe637b28f51af99ab1ca5fe558254c4811), uint256(0x20bbf048411633c27b31a3b4e8c16a2089ea7957447924b6e18647f5c3efc87f));
        vk.gamma_abc[5] = Pairing.G1Point(uint256(0x064c8f89156e36e3b67fd272cd8b7d13f0bc1c6cc0c9b437fdc46c6fa729de48), uint256(0x2eb7ca0ec2f68dd778c839ee351c0a82efbb7ac6eb1f6ec4795a7e41bdf59452));
        vk.gamma_abc[6] = Pairing.G1Point(uint256(0x03c2fe2edc9a567867026392908b41d147c63327722dce874bed9ec6134914ba), uint256(0x033198b52d2450ba30464e0980e98824d0975a5141051a21dc9ef838d9a51f69));
        vk.gamma_abc[7] = Pairing.G1Point(uint256(0x09494dee34d4589213d751db8d4c1c316c21783294904ed1f97997623b4190ec), uint256(0x1f381545575ba2706043cb019206ad1fdcd772398fd0f7998e341fbb3da05981));
        vk.gamma_abc[8] = Pairing.G1Point(uint256(0x1632e50fddb2f135b2b5573340433e65e0714c530becb3dd4bd1c226959137a3), uint256(0x04fea3deb656c64c82ae6ed2f924c41456df208bd723146820c3ab6b785a6395));
        vk.gamma_abc[9] = Pairing.G1Point(uint256(0x28e27b7563a44a52f18a9b4331f87b25ab5af8d980a28315b609ab244acf58c6), uint256(0x2fc28f18b43c0c7028d178bc991140909f3941a557e3a7308a65a87353488d9e));
        vk.gamma_abc[10] = Pairing.G1Point(uint256(0x0e705041f94322ca8756acb164b1c6599e95477456749590e7de1fa80911583a), uint256(0x2fc98913ffa4afa4e35282509c86b682e6f2db53ee73491ff014deeaa12ed044));
        vk.gamma_abc[11] = Pairing.G1Point(uint256(0x18e6932ec08be7aa2941cb3df773c922226209e09b4b24fbc8c5057a68a3c704), uint256(0x1a216f923fa50ccdcdc54b71b4912ca34227b9ab1dc30dde17ad2621dd3ce7f6));
        vk.gamma_abc[12] = Pairing.G1Point(uint256(0x0469142ca2383645a60681c28d2931f49fd17d44343f14230e08de293e53e648), uint256(0x245a94a4a60b57798deed81374eab16d23bdbfc6aaf66f480020c007ffcfcbc6));
        vk.gamma_abc[13] = Pairing.G1Point(uint256(0x14c4a4128d4fef74185ab612feb21209b48e7113647db1ed83996b6d3c73f4f6), uint256(0x2a544a1342cd5a28601ad4d154fdfef577972b1dda8b3b7d4221b7df3e3e8e16));
        vk.gamma_abc[14] = Pairing.G1Point(uint256(0x13525a8ff48fdf7cb99af9e2529c5617c003d52bd84e0e8c764f5fe07086c992), uint256(0x211a0fb0985c45d70d124b2b6411e1907a5066eb4fbc83cb9a0a52643f47701f));
        vk.gamma_abc[15] = Pairing.G1Point(uint256(0x29edd587a7e502debc1d2d7bd1df2c88a4c01f5588f29375a8941bf49418c0fb), uint256(0x1d492ecf88c430e11bbfc66d82fde1a6d6aa228bcdce19a3e78a25099aea544d));
        vk.gamma_abc[16] = Pairing.G1Point(uint256(0x098b1425a0f108f7f01b0a5b6fe1714511f5955d2c7bd25664de5d0f66a672ce), uint256(0x1ce6f96bbd270429b40791f36c7cc76055a4845de0f6d7f2c6c6d63d281e1be5));
        vk.gamma_abc[17] = Pairing.G1Point(uint256(0x0df81837aa6421deb0be9eed5797bb0e5c441f700959f7842bc6598a798579d9), uint256(0x01ba643fcaa287fceecce0840b663400f172d7c45ae7935aa5706565f2b511fe));
        vk.gamma_abc[18] = Pairing.G1Point(uint256(0x1ebfd51d345a20a49239dc2b306060501ba1f6e8ee8a7315697ab7965ad2d861), uint256(0x1d7f97a5f9959c7b048395c56164e3e9e884247a7d3d8fa077a6e84dbe7b2a07));
        vk.gamma_abc[19] = Pairing.G1Point(uint256(0x244e3cdfd1f52f25619300ee52ccaaa1a192d9826509d2c102c460f8315caea6), uint256(0x05a72b74b78353f70fe5f3fba7c32b1a153c2f44de966b662440dfbe4f2712cb));
    }
    function verify(uint[] memory input, Proof memory proof) internal view returns (uint) {
        uint256 snark_scalar_field = 21888242871839275222246405745257275088548364400416034343698204186575808495617;
        VerifyingKey memory vk = verifyingKey();
        require(input.length + 1 == vk.gamma_abc.length);
        // Compute the linear combination vk_x
        Pairing.G1Point memory vk_x = Pairing.G1Point(0, 0);
        for (uint i = 0; i < input.length; i++) {
            require(input[i] < snark_scalar_field);
            vk_x = Pairing.addition(vk_x, Pairing.scalar_mul(vk.gamma_abc[i + 1], input[i]));
        }
        vk_x = Pairing.addition(vk_x, vk.gamma_abc[0]);
        if(!Pairing.pairingProd4(
             proof.a, proof.b,
             Pairing.negate(vk_x), vk.gamma,
             Pairing.negate(proof.c), vk.delta,
             Pairing.negate(vk.alpha), vk.beta)) return 1;
        return 0;
    }

    function transfer(
            bytes32 from,
            bytes32, to,
            uint fromBalance,
            uint toBalance,
            uint amount,
            uint nonce,
            Proof memory proof,
            uint[19] memory input,
            bytes32 fromLeaf,
            bytes32 toLeaf,
            bytes32[] memory frommerkleproof,
            bytes32[] memory tomerkleproof
    ) public view returns (bool) {
        uint[] memory inputValues = new uint[](19);

        for (uint i = 0; i < input.length; i++) {
            inputValues[i] = input[i];
        }

        if (verify(inputValues, proof) == 0) {

            bytes32 keccak = keccak256(abi.encodePacked(input[2],input[3],input[4],input[5],input[6],input[7],input[8],input[9],input[10],input[11],input[12],input[13],input[14],input[15],input[16],input[17]);
            require(verifyMessage(keccak, from, to, amount, nonce));
            require(verifyLeaf(from, fromBalance, fromLeaf));
            require(verifyLeaf(to, toBalance, toLeaf));
            require(verifyMerkle(rootHash, fromLeaf, frommerkleproof));
            require(verifyMerkle(rootHash, toLeaf, tomerkleproof));

            return true;
        } else {
            return false;
        }
    }

    function verifyMessage(
        bytes32 keccak,
        bytes32 from,
        bytes32, to,
        uint amount,
        uint nonce
    ) public pure returns (bool) {
        return keccak256(abi.encodePacked(from, to, amount, nonce)) == keccak;
    }

    function newRootHash(
        bytes32 pubkey,
        uint balance,
        bytes32[] memory proof
    ) public pure returns (bytes32) {
        bytes32 computedHash = keccak256(abi.encodePacked(pubkey, balance));

        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];

            if (computedHash <= proofElement) {
                // Hash(current computed hash + current element of the proof)
                computedHash = keccak256(abi.encodePacked(computedHash, proofElement));
            } else {
                // Hash(current element of the proof + current computed hash)
                computedHash = keccak256(abi.encodePacked(proofElement, computedHash));
            }
        }
        // Check if the computed hash (root) is equal to the provided root
        return computedHash;
    }

    function verifyLeaf(
        bytes32 pubkey,
        uint balance,
        bytes32 leaf
    ) public pure returns (bool) {
        return keccak256(abi.encodePacked(pubkey, balance)) == leaf;
    }

    function verifyMerkle(
        bytes32 root,
        bytes32 leaf,
        bytes32[] memory proof
    ) public pure returns (bool) {
        bytes32 computedHash = leaf;

        for (uint256 i = 0; i < proof.length; i++) {
            bytes32 proofElement = proof[i];

            if (computedHash <= proofElement) {
                // Hash(current computed hash + current element of the proof)
                computedHash = keccak256(abi.encodePacked(computedHash, proofElement));
            } else {
                // Hash(current element of the proof + current computed hash)
                computedHash = keccak256(abi.encodePacked(proofElement, computedHash));
            }
        }
        // Check if the computed hash (root) is equal to the provided root
        return computedHash == root;
    }
}
