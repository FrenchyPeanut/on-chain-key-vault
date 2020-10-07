import { AES, enc, lib } from 'crypto-js';
import { ethers, Contract, Signer, constants } from 'ethers';
import { BytesLike } from "@ethersproject/bytes";
import {
    HDNode,
    defaultPath
  } from "@ethersproject/hdnode";

export const generateSymmetricEncryptionKey = async () => {
    const salt_ = lib.WordArray.random(128 / 8);
    return salt_.toString();
}

export const generateHDWallet = async (salt_: string, signer: Signer) => {
    const messageId = ethers.utils.id(salt_);
    const message_bytes = ethers.utils.arrayify(messageId);
    let signature: BytesLike = await signer.signMessage(message_bytes);
    return await HDNode.fromSeed(ethers.utils.arrayify(signature.substr(0, signature.length - 2))).derivePath(defaultPath);
}

export const getInitialSharedKey = async (userKey: any) => {
    const buffer_ = Buffer.from(userKey, 'hex');
    const parsedPayload = {
      iv: Buffer.from(buffer_.toString('hex', 0, 16), 'hex'), // 16 bytes
      ephemPublicKey: Buffer.from(buffer_.toString('hex', 16, 81), 'hex'), // 65 bytes
      ciphertext: Buffer.from(buffer_.toString('hex', 81, buffer_.length - 32), 'hex'), // var bytes
      mac: Buffer.from(buffer_.toString('hex', buffer_.length - 32, buffer_.length), 'hex') // 32 bytes
    };
    return parsedPayload;
  }

export const getStringifiedPayload = async (encryptedObject: any) => {
    return Buffer.concat([
        encryptedObject.iv,
        encryptedObject.ephemPublicKey,
        encryptedObject.ciphertext,
        encryptedObject.mac,
      ]).toString('hex');
}
