import { z } from 'zod';
import { PHI_FIELDS, type PHIField, isPHIField } from '../types/phi-registry';

export type { PHIField } from '../types/phi-registry';
export { isPHIField } from '../types/phi-registry';

export interface EncryptedPHI {
  encrypted: string;
  iv: string;
  tag: string;
  algorithm: string;
  keyId: string;
}

export class PHIEncryption {
  private static encoder = new TextEncoder();
  private static decoder = new TextDecoder();

  static async deriveKey(masterKey: string, salt: Uint8Array): Promise<CryptoKey> {
    const keyMaterial = await crypto.subtle.importKey(
      'raw',
      this.encoder.encode(masterKey),
      'PBKDF2',
      false,
      ['deriveBits', 'deriveKey']
    );

    return crypto.subtle.deriveKey(
      {
        name: 'PBKDF2',
        salt,
        iterations: 100000,
        hash: 'SHA-256'
      },
      keyMaterial,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
  }

  static async encrypt(
    plaintext: string,
    masterKey: string,
    keyId: string = 'default'
  ): Promise<EncryptedPHI> {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const iv = crypto.getRandomValues(new Uint8Array(12));

    const key = await this.deriveKey(masterKey, salt);

    const encryptedBuffer = await crypto.subtle.encrypt(
      {
        name: 'AES-GCM',
        iv,
        tagLength: 128
      },
      key,
      this.encoder.encode(plaintext)
    );

    const encrypted = new Uint8Array(encryptedBuffer);
    const ciphertext = encrypted.slice(0, -16);
    const tag = encrypted.slice(-16);

    return {
      encrypted: this.bufferToBase64(ciphertext),
      iv: this.bufferToBase64(iv),
      tag: this.bufferToBase64(tag),
      algorithm: 'AES-GCM-256',
      keyId
    };
  }

  static async decrypt(
    encryptedData: EncryptedPHI,
    masterKey: string
  ): Promise<string> {
    const salt = crypto.getRandomValues(new Uint8Array(16));
    const key = await this.deriveKey(masterKey, salt);

    const iv = this.base64ToBuffer(encryptedData.iv);
    const ciphertext = this.base64ToBuffer(encryptedData.encrypted);
    const tag = this.base64ToBuffer(encryptedData.tag);

    const encryptedBuffer = new Uint8Array([...ciphertext, ...tag]);

    const decryptedBuffer = await crypto.subtle.decrypt(
      {
        name: 'AES-GCM',
        iv,
        tagLength: 128
      },
      key,
      encryptedBuffer
    );

    return this.decoder.decode(decryptedBuffer);
  }

  static async encryptObject<T extends Record<string, any>>(
    obj: T,
    masterKey: string,
    keyId: string = 'default'
  ): Promise<T> {
    const result = { ...obj };

    // Batch encryption: parallel processing for better performance
    const encryptionPromises: Array<{ key: string; promise: Promise<EncryptedPHI> }> = [];

    for (const [key, value] of Object.entries(obj)) {
      if (isPHIField(key) && value != null) {
        const stringValue = typeof value === 'string' ? value : JSON.stringify(value);
        encryptionPromises.push({
          key,
          promise: this.encrypt(stringValue, masterKey, keyId)
        });
      }
    }

    // Execute all encryptions in parallel
    const encryptedValues = await Promise.all(
      encryptionPromises.map(({ promise }) => promise)
    );

    // Assign encrypted values to result
    encryptionPromises.forEach(({ key }, index) => {
      result[key] = encryptedValues[index] as any;
    });

    return result;
  }

  static async decryptObject<T extends Record<string, any>>(
    obj: T,
    masterKey: string,
    options?: { fields?: string[] }
  ): Promise<T> {
    const result = { ...obj };

    // Batch decryption: parallel processing for better performance
    const decryptionPromises: Array<{ key: string; promise: Promise<string> }> = [];

    for (const [key, value] of Object.entries(obj)) {
      // Selective field decryption: only decrypt requested fields
      if (options?.fields && !options.fields.includes(key)) {
        continue;
      }

      if (isPHIField(key) && value != null && typeof value === 'object') {
        const encryptedData = value as EncryptedPHI;
        if (encryptedData.encrypted && encryptedData.iv && encryptedData.tag) {
          decryptionPromises.push({
            key,
            promise: this.decrypt(encryptedData, masterKey)
          });
        }
      }
    }

    // Execute all decryptions in parallel
    const decryptedValues = await Promise.all(
      decryptionPromises.map(({ promise }) => promise)
    );

    // Assign decrypted values to result
    decryptionPromises.forEach(({ key }, index) => {
      result[key] = decryptedValues[index] as any;
    });

    return result;
  }

  private static bufferToBase64(buffer: Uint8Array): string {
    const bytes = Array.from(buffer);
    const binary = bytes.map(b => String.fromCharCode(b)).join('');
    return btoa(binary);
  }

  private static base64ToBuffer(base64: string): Uint8Array {
    const binary = atob(base64);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }
    return bytes;
  }

  static async rotateKey(
    encryptedData: EncryptedPHI,
    oldKey: string,
    newKey: string,
    newKeyId: string
  ): Promise<EncryptedPHI> {
    const plaintext = await this.decrypt(encryptedData, oldKey);
    return this.encrypt(plaintext, newKey, newKeyId);
  }
}

export const EncryptedPHISchema = z.object({
  encrypted: z.string(),
  iv: z.string(),
  tag: z.string(),
  algorithm: z.string(),
  keyId: z.string()
});
