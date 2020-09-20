import { Signer, Wallet, constants, Contract } from 'ethers';
import { ethers } from '@nomiclabs/buidler';
import chai from 'chai';
const { expect, assert } = chai;
import { deployContract, solidity } from 'ethereum-waffle';
import KeyVaultArtifact from '../artifacts/KeyVault.json';
import KeyVaultFactoryArtifact from '../artifacts/KeyVaultFactory.json';
import { KeyVault } from '../typechain/KeyVault';
// The Factory artifact is not stable yet, need to wait for Buidler next update
// import { KeyVaultFactory } from '../typechain/KeyVaultFactory';
import { encrypt, decrypt } from 'eccrypto';
import { AES, enc, lib } from 'crypto-js';
import {
    HDNode,
    defaultPath
} from "@ethersproject/hdnode";
import { BytesLike } from "@ethersproject/bytes";

// use(solidity); // previous EVM used for testing: -buidlerevm || However, has some issues with the block management when making regular transfers
chai.use(solidity); // Chai wrapper for solidity EVM
const ZERO = constants.AddressZero;
const log = console.log;
const pubKeyLength = 132; // Counting the 0x and 04 prefix for uncompressed key
const privKeyLength = 66; // Counting the 0x prefix
 
describe('KeyVault', () => {
    let signers: Signer[];
    let hdwallet_: HDNode;
    let hdwallet_sencondUser_: HDNode;
    let initialSeed = 'Spread your wings and prepare for a force.';
    let initialSharedKey = 'A jump to the sky turns to a rider kick.';
    let keyVault: KeyVault;
    let keyVaultFactory: Contract;
    let secretMessage = 'Unicorns and Wizards are changing the world.';
    let secretName = 'UniFi';

    before(async () => {
        signers = await ethers.getSigners();
        const salt_ = lib.WordArray.random(128 / 8);
        initialSeed = salt_.toString();
        const salt__ = lib.WordArray.random(128 / 8);
        initialSharedKey = salt__.toString();

        // The hash we wish to sign and verify:
        const messageId = ethers.utils.id(initialSeed);
        //convert string message into digest hash for better efficiency:
        const message_bytes = ethers.utils.arrayify(messageId);
        let signature: BytesLike = await signers[0].signMessage(message_bytes); // Signature of 65 bytes

        // We use the user signature as a 512-bits seed
        hdwallet_ = await HDNode.fromSeed(ethers.utils.arrayify(signature.substr(0, signature.length-2))).derivePath(defaultPath); // We remove the extra byte `v` to get a 64 bytes seed

        keyVault = (await deployContract(
            <Wallet>signers[0],
            KeyVaultArtifact,
            []
        )) as KeyVault;

        const VaultFactory = await ethers.getContractFactory('keyVaultFactory');
        keyVaultFactory = (await VaultFactory.deploy());
        await keyVaultFactory.deployed();
        await keyVaultFactory.setLibraryAddress(keyVault.address);
    });

    describe('Deployment', () => {
        it('deploy the user vault', async () => {
            const encryptedObject = await encrypt(Buffer.from(ethers.utils.computePublicKey(hdwallet_.publicKey).substr(2, pubKeyLength), 'hex'), Buffer.from(initialSharedKey));
            const stringifiedPayload = Buffer.concat([
                encryptedObject.iv,
                encryptedObject.ephemPublicKey,
                encryptedObject.ciphertext,
                encryptedObject.mac,
            ]).toString('hex');
            await expect(keyVaultFactory.createVault(stringifiedPayload, initialSeed))
            .to.emit(keyVaultFactory, 'KeyVaultDeployed');
            const userKeyVaultAddress = await keyVaultFactory.getUserKeyVaults(await signers[0].getAddress());
            keyVault = await ethers.getContractAt(KeyVaultArtifact.abi, userKeyVaultAddress) as KeyVault;
        });

        it('set the first right owner for the KeyVault contract', async () => {
            assert.isTrue(await keyVault.getWhitelistedUserStatus(await signers[0].getAddress()));
        });

        it('set the correct number of whitelisted users', async () => {
            expect(await keyVault.totalUsers()).to.equal(1);
        });

        it('cannot initialize a second time the vault', async () => {
            await expect(
                keyVault.initialize(await signers[0].getAddress(), 'sharedKey', 'initialSeed'),
            ).to.be.revertedWith('The contract must not be initialized beforehand.');
        });
    });

    describe('SharedKey management', () => {
        it('can retrieve the sharedkey and decrypt it', async () => {
            const userKey = await keyVault.getUserKeys(await signers[0].getAddress());
            const buffer_ = Buffer.from(userKey, 'hex');
            const parsedPayload = {
                iv: Buffer.from(buffer_.toString('hex', 0, 16), 'hex'), // 16 bytes
                ephemPublicKey: Buffer.from(buffer_.toString('hex', 16, 81), 'hex'), // 65 bytes // 33 bytes if uncompressed
                ciphertext: Buffer.from(buffer_.toString('hex', 81, buffer_.length - 32), 'hex'), // var bytes
                mac: Buffer.from(buffer_.toString('hex', buffer_.length - 32, buffer_.length), 'hex') // 32 bytes
            };
            const decryptedMessage = await decrypt(Buffer.from(hdwallet_.privateKey.substr(2, privKeyLength), 'hex'), parsedPayload);
            assert.equal(decryptedMessage.toString(), initialSharedKey);
        });
    });

    describe('User whitelisting management', () => {
        it('can add a new user', async () => {
            const messageId = ethers.utils.id(initialSeed);
            const message_bytes = ethers.utils.arrayify(messageId);
            let signature = await signers[2].signMessage(message_bytes);
            hdwallet_sencondUser_ = await HDNode.fromSeed(ethers.utils.arrayify(signature.substr(0, signature.length-2))).derivePath(defaultPath);
            const encryptedObject = await encrypt(Buffer.from(ethers.utils.computePublicKey(hdwallet_sencondUser_.publicKey).substr(2, pubKeyLength), 'hex'), Buffer.from(initialSharedKey));
            const stringifiedPayload = Buffer.concat([
                encryptedObject.iv,
                encryptedObject.ephemPublicKey,
                encryptedObject.ciphertext,
                encryptedObject.mac,
            ]).toString('hex');
            await keyVault.addUserKey(await signers[2].getAddress(), stringifiedPayload);
            assert.isTrue(await keyVault.getWhitelistedUserStatus(await signers[2].getAddress()));
            expect(await keyVault.totalUsers()).to.equal(2);
        });
        it('cannot add a new user if caller is not whitelisted', async () => {
            const keyVault_ = await ethers.getContractAt(
                KeyVaultArtifact.abi,
                keyVault.address,
            );
            const hackerKeyVault_ = keyVault_.connect(signers[5]);
            await expect(
                hackerKeyVault_.addUserKey(await signers[2].getAddress(), 'random_8011c03d3fd4daa125b1899c98fddec351fcfc641f560eb06f6e8d1f7dbb5474'),
            ).to.be.revertedWith('The caller must be a whitelisted member.');
        });

        it('can remove a whitelisted user', async () => {
            await keyVault.removeUser(await signers[2].getAddress());
            assert.isFalse(await keyVault.getWhitelistedUserStatus(await signers[2].getAddress()));
            expect(await keyVault.totalUsers()).to.equal(1);
        });
        it('cannot remove a whitelisted user if caller is not whitelisted', async () => {
            const keyVault_ = await ethers.getContractAt(
                KeyVaultArtifact.abi,
                keyVault.address,
            );
            const hackerKeyVault_ = keyVault_.connect(signers[5]);
            await expect(
                hackerKeyVault_.removeUser(await signers[0].getAddress()),
            ).to.be.revertedWith('The caller must be a whitelisted member.');
        });
    });

    describe('Secrets management', () => {
        it('can add a new secret', async () => {
            const ciphertext = AES.encrypt(secretMessage, initialSharedKey).toString();
            await keyVault.setSecret(secretName, ciphertext);
            assert.equal(await keyVault.getSecret(secretName), ciphertext);
        });

        it('can retreive and verify the secret message', async () => {
            const secretValue = await keyVault.getSecret(secretName);
            const bytes = AES.decrypt(secretValue, initialSharedKey);
            const decryptedMessage = bytes.toString(enc.Utf8);
            assert.equal(decryptedMessage, secretMessage);
        })
    });

    describe('New KeyVault', () => {
        it('cannot deploy a new keyVault for the same user', async () => {
            await expect(
                keyVaultFactory.createVault('stringifiedPayload', 'initialSeed'),
            ).to.be.revertedWith('Cannot deploy another keyVault.');
        });

        it('can deploy a new keyVault for a new user', async () => {
            const keyVaultFactory_ = await ethers.getContractAt(KeyVaultFactoryArtifact.abi, keyVaultFactory.address, signers[5]);
            await keyVaultFactory_.createVault('stringifiedPayload', 'initialSeed');
            const userKeyVaultAddress = await keyVaultFactory.getUserKeyVaults(await signers[5].getAddress());
            const keyVault_ = await ethers.getContractAt(KeyVaultArtifact.abi, userKeyVaultAddress) as KeyVault;
            expect(await keyVault_.getWhitelistedUserStatus(await signers[5].getAddress())).to.be.true;
            expect(await keyVault_.getWhitelistedUserStatus(await signers[0].getAddress())).to.be.false;
            expect(await keyVault.getWhitelistedUserStatus(await signers[5].getAddress())).to.be.false;
        });
    })
});
