/// <reference path="../../../types/cap.d.ts" />
import { Cap, decoders } from "cap";
import { NetworkPacket } from "@server/types/logs/network";

export type PacketCallback = (packet: NetworkPacket) => void;

export interface INetworkSniffer {
  start(): void;
  stop(): void;
  onPacket(callback: PacketCallback): void;
  offPacket(callback: PacketCallback): void;
}

export class NetworkSniffer implements INetworkSniffer {
  private cap: Cap;
  private buffer: Buffer;
  private callbacks: PacketCallback[] = [];

  constructor(private device: string) {
    this.cap = new Cap();
    this.buffer = Buffer.alloc(65535);
  }

  start() {
    const filter = ""; // alles
    const bufSize = 10 * 1024 * 1024;
    const linkType = this.cap.open(this.device, filter, bufSize, this.buffer);

    this.cap.on("packet", (nbytes: number) => {
      const eth = decoders.Ethernet(this.buffer);
      const packet: NetworkPacket = {
        timestamp: new Date(),
        length: nbytes,
        linkType: linkType,
        ethernet: {
          srcMac: eth.info.srcmac,
          dstMac: eth.info.dstmac,
          ethertype: eth.info.type,
          payload: this.buffer.slice(14, nbytes),
        },
      };

      this.callbacks.forEach((cb) => cb(packet));
    });
  }

  stop() {
    this.cap.close();
  }

  onPacket(callback: PacketCallback) {
    this.callbacks.push(callback);
  }

  offPacket(callback: PacketCallback) {
    this.callbacks = this.callbacks.filter((cb) => cb !== callback);
  }
}
