export interface Bios {
    vendor: string;
    version: string;
    releaseDate: string;
    revision: string;
    serial: string;
}

export interface Mainboard {
    manufacturer: string;
    model: string;
    version: string;
    serial: string;
    virtual: boolean;
    bios: Bios;
}

export interface OS {
    platform: string;
    distro: string;
    release: string;
    codename: string;
    kernel: string;
    arch: string;
    hostname: string;
    fqdn: string;
    build: string;
    uefi: boolean;
    hypervisor: boolean;
}

export interface CPU {
    manufacturer: string;
    brand: string;
    family: string;
    speed: string;
    speedMax: string;
    speedMin: string;
    cores: number;
    physicalCores: number;
    performanceCores: number;
    efficiencyCores: number;
    processors: number;
    socket: string;
    virtualization: boolean;
    cache: {
        l1d: number;
        l1i: number;
        l2: number;
        l3: number;
    }
}

export interface Graphics {
    controllers: {
        vendor: string;
        model: string;
        bus: string;
        vram: number;
        vramDynamic: boolean;
    }[];
} 

export interface MemLayout {
    sticks: Array<{
        size: number;
        bank: string;
        type: string;
        ecc: boolean;
        clockSpeed: number;
        formFactor: string;
        voltageConfigured: number;
        voltageMin: number;
        voltageMax: number;
    }>
}

export interface RAM {
    total: number;
    free: number;
    used: number;
    active: number;
    available: number;
    buffers: number;
    cached: number;
    swapTotal: number;
    swapUsed: number;
    swapFree: number;
    layout: MemLayout;
}

export interface DiskLayout {
    devices: [
        {
            type: string;
            name: string;
            vendor: string;
            size: number;
            bytesPerSector: number;
            totalCylinders: number;
            totalHeads: number;
            totalSectors: number;
            totalTracks: number;
            tracksPerCylinder: number;
            sectorsPerTrack: number;
            firmwareRevision: string;
            serialNum: string;
            interfaceType: string;
            smartStatus: string;
            temperature: number;
        }
    ]
}