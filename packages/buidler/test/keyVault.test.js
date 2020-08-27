const { ethers } = require('@nomiclabs/buidler');
const { use, expect, assert } = require('chai');
const { solidity } = require('ethereum-waffle');
const { constants } = require('ethers');
const EthCrypto = require('eth-crypto');

const KeyVaultContract = require('../artifacts/KeyVault.json');
const { id } = require('ethers/lib/utils');
const eccryptoJS = require('eccrypto-js');

use(solidity); // previous EVM used for testing: -buidlerevm || However, has some issues with the block management when making regular transfers
const ZERO = constants.AddressZero;

const log = console.log;
// Change this provider if necessary: || explained above why this change was necessary
const devProvider = ' http://127.0.0.1:7545/'

describe('KeyVault', () => {
    let accounts;
    let id_1, id_2;
    let wallet_id_1, wallet_id_2;
    let initialSharedKey;
    let keyVault;
    let secretMessage = 'Unicorns and Wizards are changing the world.';
    let secretName = 'UniFi';

    before(async () => {
        let httpProvider = new ethers.providers.JsonRpcProvider(devProvider);
        accounts = await ethers.getSigners();

        id_1 = EthCrypto.createIdentity();
        id_2 = EthCrypto.createIdentity();

        // Fund the owner wallet we randomly generated above:
        const tx = await accounts[0].sendTransaction({
            to: id_1.address,
            value: ethers.utils.parseEther('0.1')
        });
        // Waiting for block confirmation
        await tx.wait();

        // Pluging the newly created accounts to our node:
        wallet_id_1 = new ethers.Wallet(id_1.privateKey).connect(httpProvider);
        wallet_id_2 = new ethers.Wallet(id_2.privateKey).connect(httpProvider);

        // log(ethers.utils.formatEther(await accounts[0].getBalance()));
        // log(ethers.utils.formatEther(await wallet_id_1.getBalance()));
        // log(wallet_id_1.address);

        initialSharedKey = eccryptoJS.randomBytes(32); // 32 bytes random symmetric encryption key
    });

    describe('Deployment', () => {
        it('deploy with randomly generated ETH wallet', async () => {
            let factory = new ethers.ContractFactory(KeyVaultContract.abi, KeyVaultContract.bytecode, wallet_id_1);
            const initialEncryptedSharedKey = EthCrypto.cipher.stringify(await EthCrypto.encryptWithPublicKey(
                id_1.publicKey, // publicKey
                initialSharedKey.toString('hex') // sharedKey
            ));
            keyVault = await factory.deploy(initialEncryptedSharedKey);
        });

        it('set the first right owner for the KeyVault contract', async () => {
            assert.isTrue(await keyVault.getWhitelistedUserStatus(wallet_id_1.address));
        });

        it('set the correct number of whitelisted users', async () => {
            expect(await keyVault.totalUsers()).to.equal(1);
        })
    });

    // describe('SharedKey management', () => {
    //     it('can retrieve the sharedkey and decrypt it', async () => {
    //         // const userKey = await keyVault.getUserKeys(wallet_id_1.address);
    //         log(initialSharedKey.toString("base64"))
    //         const initialEncryptedSharedKey = await EthCrypto.encryptWithPublicKey(
    //             id_1.publicKey, // publicKey
    //             'My name is Satoshi Buterin My name is Satoshi Buterin My name is Satoshi Buterin' // 'test' // initialSharedKey.toString('hex') // sharedKey
    //         );

    //         const encryptedObject = EthCrypto.cipher.parse(initialEncryptedSharedKey);
    
    //         const decrypted = await EthCrypto.decryptWithPrivateKey(
    //             id_1.privateKey,
    //             encryptedObject
    //         );
    //         log(decrypted);
    //     })
    // })

    describe('User whitelisting management', () => {
        it('can add a new user', async () => {
            const newUserEncryptedSharedKey = EthCrypto.cipher.stringify(await EthCrypto.encryptWithPublicKey(
                id_2.publicKey, // publicKey
                initialSharedKey.toString('hex') // sharedKey
            ));
            await keyVault.addUserKey(wallet_id_2.address, newUserEncryptedSharedKey);
            assert.isTrue(await keyVault.getWhitelistedUserStatus(wallet_id_2.address));
            expect(await keyVault.totalUsers()).to.equal(2);
        });
        it('cannot add a new user if caller is not whitelisted', async () => {
            const keyVault_ = await ethers.getContractAt(
                KeyVaultContract.abi,
                keyVault.address,
            );
            const hackerKeyVault_ = keyVault_.connect(accounts[5]);
            await expect(
                hackerKeyVault_.addUserKey(await accounts[2].getAddress(), 'random_8011c03d3fd4daa125b1899c98fddec351fcfc641f560eb06f6e8d1f7dbb5474'),
            ).to.be.revertedWith('The caller must be a whitelisted member.');
        });

        it('can remove a whitelisted user', async () => {
            await keyVault.removeUser(wallet_id_2.address);
            assert.isFalse(await keyVault.getWhitelistedUserStatus(wallet_id_2.address));
            expect(await keyVault.totalUsers()).to.equal(1);
        });
        it('cannot remove a whitelisted user if caller is not whitelisted', async () => {
            const keyVault_ = await ethers.getContractAt(
                KeyVaultContract.abi,
                keyVault.address,
            );
            const hackerKeyVault_ = keyVault_.connect(accounts[5]);
            await expect(
                hackerKeyVault_.removeUser(wallet_id_1.address),
            ).to.be.revertedWith('The caller must be a whitelisted member.');
        });

    });

    describe('Secrets management', () => {
        it('can add a new secret', async () => {
            const iv = eccryptoJS.randomBytes(16);
            const secretMessageBytes = eccryptoJS.utf8ToBuffer(secretMessage);
            const ciphertext = await eccryptoJS.aesCbcEncrypt(iv, initialSharedKey, secretMessageBytes);
            const stringifiedPayload = Buffer.concat([
                iv,
                ciphertext,
            ]).toString('hex');
            await keyVault.setSecret(secretName, stringifiedPayload);
            assert.equal(await keyVault.getSecret(secretName), stringifiedPayload);
        });

        it('can retreive and verify the secret message', async () => {
            const secretValue = await keyVault.getSecret(secretName);
            const buffer_ = Buffer.from(secretValue, 'hex');
            const parsedPayload = {
                iv: buffer_.toString('hex', 0, 16),
                ciphertext: buffer_.toString('hex', 16, buffer_.length)
            };
            const decryptedMessage = await eccryptoJS.aesCbcDecrypt(Buffer.from(parsedPayload.iv, 'hex'), initialSharedKey, Buffer.from(parsedPayload.ciphertext, 'hex'));
            assert.equal(decryptedMessage, secretMessage);
        })
    })

});
