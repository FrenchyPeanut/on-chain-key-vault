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
const ZERO = constants.AddressZero;

const log = console.log;
// let web3: Web3;
let provider: any;
let signer: Signer;
let keyVaultFactory_: Contract;
let keyVault_: Contract;
let hdwallet_: any;

let initialSeed: string;
let sharedKey: string;

// Change this value to the one you have on your network:
// Ropsten address of the Vault Factory:
const initialFactoryAddress: string = '0x8D620f116896361b8dD426ab56ae12a2697e6c14';

function App() {

  const [address, setAddress] = useState('0x');
  const [balance, setBalance] = useState('0');
  // const [initialSeed, setInitialSeed] = useState('.');
  // const [sharedKey, setsharedKey] = useState('.');
  const [keyVaultAddress, setKeyVaultAddress] = useState('');
  // const [keyVaultFactoryAddress, setKeyVaultFactoryAddress] = useState(initialFactoryAddress);
  const [derivedPubKey, setDerivedPubKey] = useState('');
  const [hasVault, setHasVault] = useState(false);
  const [secretName, setSecretName] = useState('');
  const [secretName_, setSecretName_] = useState('');
  const [secretValue, setSecretValue] = useState('');
  const [secretValue_, setSecretValue_] = useState('');
  const [publicKeyAdd, setPublicKeyAdd] = useState('');
  const [addressAdd, setAddressAdd] = useState('');
  const [addressRemove, setAddressRemove] = useState('');
  const [vaultAddress, setVaultAddress] = useState('');

  const loadBlockChain = async () => {
    const providerOptions = {
    };
    const web3Modal = new Web3Modal({
      // network: 'mainnet', // optional
      // network: 'ropsten', // optional
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
    // loadVault();
  }

  const loadDerivedAccount = async (salt_: string) => {
    const messageId = ethers.utils.id(salt_);
    const message_bytes = ethers.utils.arrayify(messageId);
    let signature = await signer.signMessage(message_bytes);
    hdwallet_ = HDWallet.fromMnemonic(signature);
    setDerivedPubKey(`0x${hdwallet_.derive(`m/44'/60'/0'/0/0`).getPublicKey().toString('hex')}`);
    setHasVault(true);
  }

  const loadVault = async () => {
    loadKeyVaultFactoryContract(initialFactoryAddress);
    const userKeyVaultAddress = await keyVaultFactory_.getUserKeyVaults(await signer.getAddress());
    setKeyVaultAddress(userKeyVaultAddress);
    if (userKeyVaultAddress != ZERO) { // && loadingAccount) {
      loadKeyVaultContract(userKeyVaultAddress);
      const salt_ = await keyVault_.salt();
      await loadDerivedAccount(salt_);
    }
  }

  const generateSymmetricEncryptionKey = async () => {
    const salt_ = lib.WordArray.random(128 / 8);
    initialSeed = salt_.toString();
  }

  const generateSecondSymmetricEncryptionKey = async () => {
    const salt_ = lib.WordArray.random(128 / 8);
    sharedKey = salt_.toString();
  }

  const deployVault = async () => {
    await generateSymmetricEncryptionKey();
    await generateSecondSymmetricEncryptionKey();
    const messageId = ethers.utils.id(initialSeed);
    const message_bytes = ethers.utils.arrayify(messageId);
    let signature = await signer.signMessage(message_bytes);
    const hdwallet = HDWallet.fromMnemonic(signature);
    const encryptedObject = await encrypt(Buffer.from('04' + await hdwallet.derive(`m/44'/60'/0'/0/0`).getPublicKey().toString('hex'), 'hex'), Buffer.from(sharedKey));

    const stringifiedPayload = Buffer.concat([
      encryptedObject.iv,
      encryptedObject.ephemPublicKey,
      encryptedObject.ciphertext,
      encryptedObject.mac,
    ]).toString('hex');
    loadKeyVaultFactoryContract(initialFactoryAddress);
    const tx = await keyVaultFactory_.createVault(stringifiedPayload, initialSeed);
    await tx.wait();
    const userKeyVaultAddress = await keyVaultFactory_.getUserKeyVaults(await signer.getAddress());
    setKeyVaultAddress(userKeyVaultAddress);
    setDerivedPubKey(`0x${hdwallet.derive(`m/44'/60'/0'/0/0`).getPublicKey().toString('hex')}`);
  }

  const connectToVault = async () => {
    if (vaultAddress != ZERO) {
      setKeyVaultAddress(vaultAddress);
      loadKeyVaultContract(vaultAddress);
      const salt__ = await keyVault_.salt();
      if (salt__ != '') {
        await loadDerivedAccount(salt__);
      }
    }
  }

  const loadKeyVaultContract = async (address_: string) => {
    keyVault_ = new ethers.Contract(address_, KeyVaultArtifact.abi, signer);
  }

  const loadKeyVaultFactoryContract = async (address_: string) => {
    keyVaultFactory_ = new ethers.Contract(initialFactoryAddress, KeyVaultFactoryArtifact.abi, signer);
  }

  const getSecret = async () => {
    if (await keyVault_.getWhitelistedUserStatus(signer.getAddress())) {
      const initialSharedKey = await decrypt(await hdwallet_.derive(`m/44'/60'/0'/0/0`).getPrivateKey(), await getInitialSharedKey());
      const secretValue = await keyVault_.getSecret(secretName_);
      const bytes = AES.decrypt(secretValue, initialSharedKey.toString());
      const decryptedMessage = bytes.toString(enc.Utf8);
      setSecretValue_(decryptedMessage);
    }
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
    if (await keyVault_.getWhitelistedUserStatus(signer.getAddress())) {
      const initialSharedKey = await decrypt(await hdwallet_.derive(`m/44'/60'/0'/0/0`).getPrivateKey(), await getInitialSharedKey());
      const ciphertext = AES.encrypt(secretValue, initialSharedKey.toString()).toString();
      await keyVault_.setSecret(secretName, ciphertext);
    }
  }

  const AddUserPublicKey = async () => {
    if (await keyVault_.getWhitelistedUserStatus(signer.getAddress())) {
      const initialSharedKey = await decrypt(await hdwallet_.derive(`m/44'/60'/0'/0/0`).getPrivateKey(), await getInitialSharedKey());
      const encryptedObject = await encrypt(Buffer.from('04' + publicKeyAdd.slice(2, publicKeyAdd.length), 'hex'), Buffer.from(initialSharedKey.toString('hex'), 'hex'));
      const stringifiedPayload = Buffer.concat([
        encryptedObject.iv,
        encryptedObject.ephemPublicKey,
        encryptedObject.ciphertext,
        encryptedObject.mac,
      ]).toString('hex');
      await keyVault_.addUserKey(addressAdd, stringifiedPayload);
      setPublicKeyAdd('');
    }
  }

  const RemoveUserPublicKey = async () => {
    if (await keyVault_.getWhitelistedUserStatus(signer.getAddress())) {
      await keyVault_.removeUser(addressRemove);
      setAddressRemove('');
    }
  }

  const logoutVault = () => {
    setHasVault(false);
    setKeyVaultAddress('');
    setDerivedPubKey('');
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
          Derived public-key account:  {derivedPubKey}<br />
          <span className='smoltext'>(Share your derived public-key to get whitelisted in a vault, but please note that your derived public-key is unique to each vault)</span>
          <br />
          Vault address:  {keyVaultAddress}
          <br />
        </span>
      </header>
      <div className='contractStuff' hidden={hasVault}>
        <button onClick={deployVault}>Deploy Vault</button>
        <br /><br />
        <div className='structStuff'>
          <div className='structContent'>
            <textarea placeholder='Vault address' onChange={(e) => {
              setVaultAddress(e.target.value);
            }}></textarea>
            <button onClick={connectToVault}>Connect to vault</button>
          </div>
        </div>
        <br /><br />
        <button onClick={loadVault}>Connect to personal vault</button>
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

      <div className='contractStuff' hidden={!hasVault}>
        <br />
        <div className='structStuff'>
          <div className='structContent'>
            <button onClick={logoutVault}>Logout from Vault</button> <br />
          </div>
        </div>
        <br />
      </div>

    </div>
  );
}

export default App;
