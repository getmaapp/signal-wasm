export {};

declare global {
  interface Window {
    __lastMessage?: {
      ciphertext: Uint8Array;
      type: number;
      senderUuid: string;
      senderDeviceId: number;
    };
    __groupDistId?: string;
    __lastInfoMessage?: {
      senderUuid: string;
      senderDeviceId: number;
      distMessage: Uint8Array;
    };
    __lastGroupMessage?: {
      ciphertext: Uint8Array;
      senderUuid: string;
      senderDeviceId: number;
    };
  }
}
