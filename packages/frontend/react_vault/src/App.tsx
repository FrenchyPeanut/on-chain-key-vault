import React, { useState, useEffect } from 'react';
import logo from './pepe_coder.png';
import './App.css';
// Uncomment if you want to use web3: import Web3 from 'web3';
import { ethers, Contract, Signer, constants } from 'ethers';
import Web3Modal from 'web3modal';

import KeyVaultArtifact from './artifacts/KeyVault.json';
import KeyVaultFactoryArtifact from './artifacts/KeyVaultFactory.json';
import { encrypt, decrypt } from 'eccrypto';
import { AES, enc, lib } from 'crypto-js';

const HDWallet = require('ethereum-hdwallet');
const publicKeyToAddress = require('ethereum-public-key-to-address')
const ZERO = constants.AddressZero;

const log = console.log;
// let web3: Web3;
let provider: any;
let signer: Signer;
let keyVaultFactory_: Contract;
let keyVault_: Contract;
let hdwallet_: any;

function App() {

  const [address, setAddress] = useState('0x');
  const [balance, setBalance] = useState('0');
  const [initialSeed, setInitialSeed] = useState('');
  const [keyVaultAddress, setKeyVaultAddress] = useState('');
  const [keyVaultFactoryAddress, setKeyVaultFactoryAddress] = useState('0xeD77D9a0Ca285554564556648bfB852Ee5a7F7E7');
  const [derivedPubKey, setDerivedPubKey] = useState('');
  const [hasVault, setHasVault] = useState(false);
  const [secretName, setSecretName] = useState('');
  const [secretName_, setSecretName_] = useState('');
  const [secretValue, setSecretValue] = useState('');
  const [secretValue_, setSecretValue_] = useState('');
  const [publicKeyAdd, setPublicKeyAdd] = useState('');
  const [addressAdd, setAddressAdd] = useState('');
  const [addressRemove, setAddressRemove] = useState('');

  const loadBlockChain = async () => {
    const providerOptions = {
    };
    const web3Modal = new Web3Modal({
      // network: 'mainnet', // optional
      cacheProvider: true, // optional
      providerOptions
    });
    provider = await web3Modal.connect();
    // If you want to use web3, uncomment this: web3 = new Web3(provider);
    const provider_ = new ethers.providers.Web3Provider(provider);
    signer = provider_.getSigner();
    setAddress(await signer.getAddress());
    const balance = await provider_.getBalance(await signer.getAddress());
    setBalance(ethers.utils.formatEther(balance));
    loadVault();
  }

  const loadDerivedAccount = async (salt_: string) => {
    const messageId = ethers.utils.id(salt_);
    const message_bytes = ethers.utils.arrayify(messageId);
    let signature = await signer.signMessage(message_bytes);
    hdwallet_ = HDWallet.fromMnemonic(signature);
    setDerivedPubKey(`0x${hdwallet_.derive(`m/44'/60'/0'/0/0`).getPublicKey().toString('hex')}`);
  }

  const loadVault = async () => {
    keyVaultFactory_ = new ethers.Contract(keyVaultFactoryAddress, KeyVaultFactoryArtifact.abi, signer);
    const userKeyVaultAddress = await keyVaultFactory_.getUserKeyVaults(await signer.getAddress());
    setKeyVaultAddress(userKeyVaultAddress);
    if (userKeyVaultAddress != ZERO) { // && loadingAccount) {
      setHasVault(true);
      keyVault_ = new ethers.Contract(userKeyVaultAddress, KeyVaultArtifact.abi, signer);
      const salt_ = await keyVault_.salt();
      await loadDerivedAccount(salt_);
    }
  }

  const generateSymmetricEncryptionKey = async () => {
    const salt_ = lib.WordArray.random(128 / 8);
    setInitialSeed(salt_.toString());
  }

  const deployVault = async () => {
    await generateSymmetricEncryptionKey();
    const messageId = ethers.utils.id(initialSeed);
    const message_bytes = ethers.utils.arrayify(messageId);
    let signature = await signer.signMessage(message_bytes);
    const hdwallet = HDWallet.fromMnemonic(signature);
    const encryptedObject = await encrypt(Buffer.from('04' + await hdwallet.derive(`m/44'/60'/0'/0/0`).getPublicKey().toString('hex'), 'hex'), Buffer.from(initialSeed));
    
    const stringifiedPayload = Buffer.concat([
      encryptedObject.iv,
      encryptedObject.ephemPublicKey,
      encryptedObject.ciphertext,
      encryptedObject.mac,
    ]).toString('hex');
    const tx = await keyVaultFactory_.createVault(stringifiedPayload, initialSeed);
    await tx.wait();
    const userKeyVaultAddress = await keyVaultFactory_.getUserKeyVaults(await signer.getAddress());
    setKeyVaultAddress(userKeyVaultAddress);
    setDerivedPubKey(`0x${hdwallet.derive(`m/44'/60'/0'/0/0`).getPublicKey().toString('hex')}`);
  }

  const getSecret = async () => {
    const initialSharedKey = await decrypt(await hdwallet_.derive(`m/44'/60'/0'/0/0`).getPrivateKey(), await getInitialSharedKey());
    const secretValue = await keyVault_.getSecret(secretName_);
    const bytes = AES.decrypt(secretValue, initialSharedKey.toString());
    const decryptedMessage = bytes.toString(enc.Utf8);
    setSecretValue_(decryptedMessage);
  }

  const getInitialSharedKey = async () => {
    const userKey = await keyVault_.getUserKeys(await signer.getAddress());
    const buffer_ = Buffer.from(userKey, 'hex');
    const parsedPayload = {
      iv: Buffer.from(buffer_.toString('hex', 0, 16), 'hex'), // 16 bits
      ephemPublicKey: Buffer.from(buffer_.toString('hex', 16, 81), 'hex'), // 65 bits // 33 bits if uncompressed
      ciphertext: Buffer.from(buffer_.toString('hex', 81, buffer_.length - 32), 'hex'), // var bits
      mac: Buffer.from(buffer_.toString('hex', buffer_.length - 32, buffer_.length), 'hex') // 32 bits
    };
    return parsedPayload;
  }

  const setSecret = async () => {
    const initialSharedKey = await decrypt(await hdwallet_.derive(`m/44'/60'/0'/0/0`).getPrivateKey(), await getInitialSharedKey());
    const ciphertext = AES.encrypt(secretValue, initialSharedKey.toString()).toString();
    await keyVault_.setSecret(secretName, ciphertext);
  }

  const AddUserPublicKey = async () => {
    const initialSharedKey = await decrypt(await hdwallet_.derive(`m/44'/60'/0'/0/0`).getPrivateKey(), await getInitialSharedKey());
    const encryptedObject = await encrypt(Buffer.from(publicKeyAdd, 'hex'), Buffer.from(initialSharedKey));
    const stringifiedPayload = Buffer.concat([
      encryptedObject.iv,
      encryptedObject.ephemPublicKey,
      encryptedObject.ciphertext,
      encryptedObject.mac,
    ]).toString('hex');
    await keyVault_.addUserKey(addressAdd, stringifiedPayload);
    setPublicKeyAdd('');
  }

  const RemoveUserPublicKey = async () => {
    await keyVault_.removeUser(addressRemove);
    setAddressRemove('');
  }

  useEffect(() => {
    loadBlockChain();
  }, []);

  return (

    <div className='App'>
      <header className='App-header'>
        <img src={logo} className='App-logo' alt='logo' />
        <span>
          On-chain Vault for the Jarvis Blockchain challenge
        </span>
        <span className='accountDetails'>
          <br /><br />
          Connected Wallet:  {address}
          <br />
          Wallet Balance:  {balance} ETH
          <br />
          Derived public-key account:  {derivedPubKey}
          <br />
          Vault address:  {keyVaultAddress}
          <br />
        </span>
      </header>
      <div className='contractStuff' hidden={hasVault}>
        <button onClick={deployVault}>Deploy Vault</button>
      </div>

      <div className='contractStuff' hidden={!hasVault}>
        <br />
        <span className='textStyle'>Secret Management</span>
        <br /><br />
        <div className='structStuff'>
          <div className='structContent'>
            <textarea placeholder='Secret Name' onChange={(e) => {
              setSecretName(e.target.value);
            }}></textarea>
            <textarea placeholder='Secret Value' onChange={(e) => {
              setSecretValue(e.target.value);
            }}></textarea>
            <button onClick={setSecret}>Add Secret</button>
          </div>
        </div>
        <br />
        <div className='structStuff'>
          <div className='structContent'>
            <textarea placeholder='Secret Name' onChange={(e) => {
              setSecretName_(e.target.value);
            }}></textarea>
            <button onClick={getSecret}>Get Secret</button> <br />
            <span className='textStyle'>&nbsp;&nbsp;{secretValue_}</span>
          </div>
        </div>
        <br />
      </div>

      <div className='contractStuff' hidden={!hasVault}>
        <br />
        <span className='textStyle'>User Management</span>
        <br /><br />
        <div className='structStuff'>
          <div className='structContent'>
            <textarea placeholder='User Address to add' onChange={(e) => {
              setAddressAdd(e.target.value);
            }}></textarea>
            <textarea placeholder='Derived Public-Key to add' onChange={(e) => {
              setPublicKeyAdd(e.target.value);
            }}></textarea>
            <button onClick={AddUserPublicKey}>Add User</button>
          </div>
        </div>
        <br />
        <div className='structStuff'>
          <div className='structContent'>
            <textarea placeholder='User Address to remove' onChange={(e) => {
              setAddressRemove(e.target.value);
            }}></textarea>
            <button onClick={RemoveUserPublicKey}>Remove User</button> <br />
          </div>
        </div>
        <br />
      </div>

    </div>
  );
}

export default App;
