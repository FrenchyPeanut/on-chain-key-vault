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
import {
  HDNode,
  defaultPath
} from "@ethersproject/hdnode";
import { generateSymmetricEncryptionKey, generateHDWallet, getInitialSharedKey, getStringifiedPayload } from './lib'
import { BytesLike } from "@ethersproject/bytes";

const ZERO = constants.AddressZero;

// Use this to debug code:
const log = console.log;
// Uncomment web3 if you need to change it from ethers
// let web3: Web3;
let provider: any;
let signer: Signer;
let keyVaultFactory_: Contract;
let keyVault_: Contract;
let hdwallet_: HDNode;

let initialSeed: string;
let sharedKey: string;

const pubKeyLength = 132; // Counting the 0x and 04 prefix for uncompressed key
const privKeyLength = 66; // Counting the 0x prefix

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
  const [logText, setLogText] = useState('Welcome sir');

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
  }

  const loadDerivedAccount = async (salt_: string) => {
    hdwallet_ = await generateHDWallet(salt_, signer);
    setDerivedPubKey(`${ethers.utils.computePublicKey(hdwallet_.publicKey)}`);
    setHasVault(true);
    setLogText('Successfully connected to Vault');
  }

  const loadVault = async () => {
    loadKeyVaultFactoryContract(initialFactoryAddress);
    const userKeyVaultAddress = await keyVaultFactory_.getUserKeyVaults(await signer.getAddress());
    setKeyVaultAddress(userKeyVaultAddress);
    if (userKeyVaultAddress !== ZERO) {
      loadKeyVaultContract(userKeyVaultAddress);
      const salt_ = await keyVault_.salt();
      await loadDerivedAccount(salt_);
    } else {
      setLogText('You do not have any deployed Vault');
    }
  }

  const deployVault = async () => {
    initialSeed = await generateSymmetricEncryptionKey();
    sharedKey = await generateSymmetricEncryptionKey();
    const messageId = ethers.utils.id(initialSeed);
    const message_bytes = ethers.utils.arrayify(messageId);
    let signature: BytesLike = await signer.signMessage(message_bytes);
    hdwallet_ = await HDNode.fromSeed(ethers.utils.arrayify(signature.substr(0, signature.length - 2))).derivePath(defaultPath);
    const encryptedObject = await encrypt(Buffer.from(ethers.utils.computePublicKey(hdwallet_.publicKey).substr(2, pubKeyLength), 'hex'), Buffer.from(sharedKey));
    const stringifiedPayload = await getStringifiedPayload(encryptedObject);
    loadKeyVaultFactoryContract(initialFactoryAddress);
    try {
      const tx = await keyVaultFactory_.createVault(stringifiedPayload, initialSeed);
      await tx.wait();
      setLogText('Vault Deployed');
    } catch (e) { setLogText('Error while deploying the Vault'); }
    const userKeyVaultAddress = await keyVaultFactory_.getUserKeyVaults(await signer.getAddress());
    setKeyVaultAddress(userKeyVaultAddress);
    setDerivedPubKey(`${ethers.utils.computePublicKey(hdwallet_.publicKey)}`);
  }

  const connectToVault = async () => {
    if (vaultAddress !== ZERO) {
      setKeyVaultAddress(vaultAddress);
      loadKeyVaultContract(vaultAddress);
      let salt__: any;
      try {
        salt__ = await keyVault_.salt();
      } catch (e) { log(e); salt__ = '' }
      if (salt__ !== '') {
        await loadDerivedAccount(salt__);
      } else {
        setLogText('Wrong Vault address');
      }
    } else {
      setLogText('Wrong Vault address');
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
      const initialSharedKey = await decrypt(Buffer.from(hdwallet_.privateKey.substr(2, privKeyLength), 'hex'), await getInitialSharedKey(await keyVault_.getUserKeys(await signer.getAddress())));
      const secretValue = await keyVault_.getSecret(secretName_);
      const bytes = AES.decrypt(secretValue, initialSharedKey.toString());
      const decryptedMessage = bytes.toString(enc.Utf8);
      setSecretValue_(decryptedMessage);
      setLogText((decryptedMessage.length !== 0) ? 'Secret Loaded' : 'Secret does not exist');
    } else {
      setLogText('You are not allowed to load secrets');
    }
  }

  const setSecret = async () => {
    if (await keyVault_.getWhitelistedUserStatus(signer.getAddress())) {
      if (secretValue.length !== 0 && secretName.length !== 0) {
        const initialSharedKey = await decrypt(Buffer.from(hdwallet_.privateKey.substr(2, privKeyLength), 'hex'), await getInitialSharedKey(await keyVault_.getUserKeys(await signer.getAddress())));
        const ciphertext = AES.encrypt(secretValue, initialSharedKey.toString()).toString();
        try {
          await keyVault_.setSecret(secretName, ciphertext);
          setLogText('Secret Added');
        } catch (e) { setLogText('Secret already exists'); }
      } else {
        setLogText(secretValue.length === 0 && secretName.length === 0 ? 'Please add values' : secretValue.length === 0 ? 'Please add a Secret value' : 'Please add a Secret name');
      }
    } else {
      setLogText('You are not authorized to add secrets');
    }
  }

  const AddUserPublicKey = async () => {
    if (await keyVault_.getWhitelistedUserStatus(signer.getAddress())) {
      if (addressAdd.length !== 0 && addressAdd !== ZERO && publicKeyAdd.length !== 0 && ethers.utils.isAddress(addressAdd)) {
        const initialSharedKey = await decrypt(Buffer.from(hdwallet_.privateKey.substr(2, privKeyLength), 'hex'), await getInitialSharedKey(await keyVault_.getUserKeys(await signer.getAddress())));
        const encryptedObject = await encrypt(Buffer.from(publicKeyAdd.slice(2, publicKeyAdd.length), 'hex'), Buffer.from(initialSharedKey.toString('hex'), 'hex'));
        const stringifiedPayload = await getStringifiedPayload(encryptedObject);
        try {
          await keyVault_.addUserKey(addressAdd, stringifiedPayload);
          setPublicKeyAdd('');
          setLogText('User added');
        } catch (e) { setLogText('Error while adding user'); }
      } else {
        setLogText(addressAdd.length === 0 && publicKeyAdd.length === 0 ? 'Please add values' : (addressAdd.length === 0 || !ethers.utils.isAddress(addressAdd)) ? 'Please add an address to add' : 'Please add a public-key to add');
      }
    } else {
      setLogText('You are not authorized to remove users');
    }
  }

  const RemoveUserPublicKey = async () => {
    if (await keyVault_.getWhitelistedUserStatus(signer.getAddress())) {
      try {
        await keyVault_.removeUser(addressRemove);
        setAddressRemove('');
        setLogText('User removed');
      } catch (e) { setLogText('Error while removing user'); }
    } else {
      setLogText('You are not authorized to remove users');
    }
  }

  const logoutVault = () => {
    setHasVault(false);
    setKeyVaultAddress('');
    setDerivedPubKey('');
    setLogText('Successfully Logged out from Vault')
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

      <div className='logConsole'>
        <span className='blink'>> </span><span>{logText}</span>
      </div>
    </div>
  );
}

export default App;
