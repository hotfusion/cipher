import * as crypto from 'crypto';
export interface EncryptedData {
    iv: string;
    tag: string;
    ciphertext: string;
}
export class Encryption {
    static encrypt(data: string, key: Buffer): EncryptedData {
        const iv = crypto.randomBytes(12);
        const cipher = crypto.createCipheriv('aes-256-gcm', key, iv);
        const ciphertext = Buffer.concat([cipher.update(data, 'utf8'), cipher.final()]);
        const tag = cipher.getAuthTag();
        return { iv: iv.toString('hex'), tag: tag.toString('hex'), ciphertext: ciphertext.toString('hex') };
    }
    static decrypt({ iv, tag, ciphertext }: EncryptedData, key: Buffer): string {
        const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(iv, 'hex'));
        decipher.setAuthTag(Buffer.from(tag, 'hex'));
        return Buffer.concat([decipher.update(Buffer.from(ciphertext, 'hex')), decipher.final()]).toString('utf8');
    }
}
