import { split, combine } from 'shamir-secret-sharing';

export class Shamir {
    static async split(secret: Uint8Array, n: number, k: number): Promise<Uint8Array[]> {
        return split(secret, n, k);
    }

    static async combine(shares: Uint8Array[]): Promise<Uint8Array> {
        return combine(shares);
    }
}